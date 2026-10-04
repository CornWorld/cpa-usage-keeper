package test

import (
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	"fmt"
	"testing"
	"time"
)

func TestArchiveRetentionCleanup(t *testing.T) {
	for _, days := range []int{0, -1, 30, 89, 90, 180, int(^uint(0) >> 1)} {
		t.Run(fmt.Sprint(days), func(t *testing.T) {
			db := openTestDatabase(t)
			now := time.Date(2026, 3, 9, 4, 30, 0, 0, time.Local)
			cutoff := time.Date(2026, 3, 9, 0, 0, 0, 0, time.Local).AddDate(0, 0, -180)
			rows := make([]entities.UsageEventArchive, 1200)
			for i := range rows {
				// 交错时间顺序，验证分批扫描不能假设 ID 与请求时间同序。
				at := cutoff.Add(-time.Second)
				if i%2 == 0 {
					at = cutoff
				}
				rows[i] = entities.UsageEventArchive{ID: int64(i + 1), EventKey: fmt.Sprint(i), Timestamp: at}
			}
			if err := db.CreateInBatches(rows, 10).Error; err != nil {
				t.Fatal(err)
			}
			hot := entities.UsageEvent{EventKey: "recent", Timestamp: now.AddDate(0, 0, -60)}
			if err := db.Create(&hot).Error; err != nil {
				t.Fatal(err)
			}
			result, err := repository.CleanupStorage(db, now, days)
			if err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if days == 90 {
				want = 1200
			}
			if days == 180 {
				want = 600
			}
			if result.UsageEventsArchiveDeleted != want {
				t.Fatalf("deleted %d, want %d", result.UsageEventsArchiveDeleted, want)
			}
			var count int64
			if err := db.Model(&entities.UsageEventArchive{}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 1200-want {
				t.Fatalf("remaining %d", count)
			}
			if err := db.Model(&entities.UsageEvent{}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatal("hot event deleted")
			}
			again, err := repository.CleanupStorage(db, now, days)
			if err != nil || again.UsageEventsArchiveDeleted != 0 {
				t.Fatalf("repeat: %+v %v", again, err)
			}
		})
	}
}
