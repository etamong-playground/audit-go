package durable

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type cleanupScan func(...any) error

func (s cleanupScan) Scan(dest ...any) error { return s(dest...) }

func TestCleanupRejectsInvalidExecutorOrLimit(t *testing.T) {
	query := func(context.Context, string, ...any) RowScanner {
		t.Fatal("invalid cleanup reached the database")
		return nil
	}
	for _, limit := range []int{-1, 0, 10001} {
		if _, err := PurgeExpiredWith(context.Background(), query, limit); err == nil {
			t.Fatalf("accepted invalid limit %d", limit)
		}
	}
	if _, err := PurgeExpiredWith(context.Background(), nil, 1); err == nil {
		t.Fatal("accepted nil executor")
	}
	if _, err := PurgeExpired(context.Background(), nil, 1); err == nil {
		t.Fatal("accepted nil database")
	}
}

func TestCleanupReturnsNoSummaryOnScanFailure(t *testing.T) {
	failure := errors.New("query unavailable")
	got, err := PurgeExpiredWith(context.Background(), func(context.Context, string, ...any) RowScanner {
		return cleanupScan(func(dest ...any) error { *dest[0].(*int64) = 9; return failure })
	}, 1)
	if !errors.Is(err, failure) || got != (CleanupSummary{}) {
		t.Fatalf("failed cleanup reported a summary: %+v, %v", got, err)
	}
}

func purgeOnTx(ctx context.Context, tx *sql.Tx, limit int) (CleanupSummary, error) {
	return PurgeExpiredWith(ctx, func(ctx context.Context, statement string, args ...any) RowScanner {
		return tx.QueryRowContext(ctx, statement, args...)
	}, limit)
}

func TestCleanupLimitIncludesEndpoints(t *testing.T) {
	for _, limit := range []int{1, 10000} {
		called := false
		summary, err := PurgeExpiredWith(context.Background(), func(_ context.Context, _ string, args ...any) RowScanner {
			called = true
			if len(args) != 1 || args[0] != limit {
				t.Fatalf("cleanup limit arguments: %v", args)
			}
			return cleanupScan(func(...any) error { return nil })
		}, limit)
		if err != nil || !called || summary != (CleanupSummary{}) {
			t.Fatalf("valid limit %d: %+v %v", limit, summary, err)
		}
	}
}

func TestCleanupNormalizesTimeRanges(t *testing.T) {
	source := time.Date(2020, 3, 1, 1, 2, 3, 0, time.FixedZone("source", 9*3600))
	summary, err := PurgeExpiredWith(context.Background(), func(context.Context, string, ...any) RowScanner {
		return cleanupScan(func(dest ...any) error {
			*dest[0].(*int64) = 1
			for i := 1; i < len(dest); i++ {
				*dest[i].(*sql.NullTime) = sql.NullTime{Time: source, Valid: true}
			}
			return nil
		})
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []*time.Time{summary.OccurredFrom, summary.OccurredTo, summary.ExpiredFrom, summary.ExpiredTo} {
		if value == nil || !value.Equal(source) || value.Location() != time.UTC {
			t.Fatalf("non-UTC cleanup range: %v", value)
		}
	}
}
