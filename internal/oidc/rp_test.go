// OIDC RP end-to-end test against an in-process mock IdP: discovery, authorize,
// PKCE token exchange, ID-token verification and single-use state handling.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// mockIdP implements the minimal OIDC provider surface: discovery, authorize, token.
type mockIdP struct {
	baseURL  string
	key      *rsa.PrivateKey
	mu       sync.Mutex
	codes    map[string]string // code -> subject
	lastCode string
}

func newMockIdP(t *testing.T) *mockIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return &mockIdP{key: key, codes: make(map[string]string)}
}

func (m *mockIdP) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q,
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": ["RS256"],
			"code_challenge_methods_supported": ["S256"]
		}`, m.baseURL, m.baseURL+"/authorize", m.baseURL+"/token", m.baseURL+"/jwks")
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(m.key.N.Bytes())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"smoke-key-1","n":%q,"e":"AQAB"}]}`, n)
	})

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Mock IdP immediately grants a code for the requested user; real flow
		// would authenticate the user here. PKCE params are recorded by the RP.
		code := fmt.Sprintf("code-%d", time.Now().UnixNano())
		m.mu.Lock()
		m.codes[code] = "user-123"
		m.mu.Unlock()
		redirect := r.URL.Query().Get("redirect_uri") + "?code=" + code + "&state=" + r.URL.Query().Get("state")
		http.Redirect(w, r, redirect, http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		code := r.PostForm.Get("code")
		m.mu.Lock()
		subject, ok := m.codes[code]
		if ok {
			delete(m.codes, code)
		}
		m.mu.Unlock()
		if !ok {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		now := time.Now()
		header := map[string]any{"typ": "JWT", "alg": string(jose.RS256), "kid": "smoke-key-1"}
		payload := map[string]any{
			"iss":   m.baseURL,
			"sub":   subject,
			"aud":   "smoke-client",
			"exp":   now.Add(10 * time.Minute).Unix(),
			"iat":   now.Unix(),
			"email": "user@example.com",
			"name":  "Smoke User",
		}
		signed, err := signIDToken(m.key, header, payload)
		if err != nil {
			t.Errorf("sign id token: %v", err)
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":%q}`, signed)
	})

	return mux
}

func TestRPFullFlow(t *testing.T) {
	idp := newMockIdP(t)
	server := httptest.NewServer(idp.handler(t))
	defer server.Close()
	idp.baseURL = server.URL

	rp := NewRP(Config{
		Issuer:       server.URL,
		ClientID:     "smoke-client",
		ClientSecret: "smoke-secret",
		RedirectURL:  "https://keeper.example.com/api/v1/auth/oidc/callback",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Start login: get authorization URL with state + PKCE challenge.
	login, err := rp.Login(ctx)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.HasPrefix(login.AuthorizationURL, server.URL+"/authorize") {
		t.Fatalf("authorization URL should point at IdP: %s", login.AuthorizationURL)
	}

	// 2. Simulate the IdP issuing a code (parse state from the auth URL).
	authURLParts := strings.SplitN(login.AuthorizationURL, "?", 2)
	if len(authURLParts) != 2 {
		t.Fatalf("authorization URL missing query: %s", login.AuthorizationURL)
	}
	query := authURLParts[1]
	state := extractQueryParam(t, query, "state")
	challenge := extractQueryParam(t, query, "code_challenge")
	if len(challenge) < 40 {
		t.Fatalf("PKCE challenge missing or too short: %q", challenge)
	}
	if method := extractQueryParam(t, query, "code_challenge_method"); method != "S256" {
		t.Fatalf("expected S256 PKCE method, got %q", method)
	}

	// 3. Mock IdP issues the code for our state.
	idp.mu.Lock()
	code := fmt.Sprintf("smoke-code-%d", time.Now().UnixNano())
	idp.codes[code] = "user-123"
	idp.mu.Unlock()

	// 4. Complete callback: token exchange + ID token verification.
	result, err := rp.Callback(ctx, state, code)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if result.Identity.Subject != "user-123" {
		t.Fatalf("subject = %q, want user-123", result.Identity.Subject)
	}
	if result.Identity.Email != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", result.Identity.Email)
	}
	if result.Identity.Name != "Smoke User" {
		t.Fatalf("name = %q, want Smoke User", result.Identity.Name)
	}

	// 5. State replay must fail (single-use).
	if _, err := rp.Callback(ctx, state, code); err == nil {
		t.Fatal("replaying consumed state+code must fail")
	}

	// 6. Unknown state must fail.
	if _, err := rp.Callback(ctx, "bogus-state", code); err == nil {
		t.Fatal("unknown state must fail")
	}
}

func extractQueryParam(t *testing.T, query, key string) string {
	t.Helper()
	for _, pair := range strings.Split(query, "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 && kv[0] == key {
			return kv[1]
		}
	}
	return ""
}

// signIDToken signs a compact JWS with RS256 using go-jose.
func signIDToken(key *rsa.PrivateKey, header, payload map[string]any) (string, error) {
	extraHeaders := make(map[jose.HeaderKey]interface{}, len(header))
	for k, v := range header {
		extraHeaders[jose.HeaderKey(k)] = v
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, &jose.SignerOptions{ExtraHeaders: extraHeaders})
	if err != nil {
		return "", err
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	object, err := signer.Sign(rawPayload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}
