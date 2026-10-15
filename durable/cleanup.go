package durable

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// RowScanner permits sql and pgx query rows without a driver dependency.
type RowScanner interface{ Scan(...any) error }

// CleanupSummary describes rows actually deleted, with inclusive UTC time ranges.
// All ranges are nil when Removed is zero. It contains no expired event payloads.
type CleanupSummary struct {
	Removed                  int64
	OccurredFrom, OccurredTo *time.Time
	ExpiredFrom, ExpiredTo   *time.Time
}

// PurgeExpiredWith deletes at most limit events using their original expiry, where limit is 1..10000.
// To retain a cleanup outcome atomically, query must use the caller's active transaction;
// record the outcome on that same transaction and roll back on any error.
// It never commits. A zero count under concurrent cleanup does not prove the backlog is empty.
func PurgeExpiredWith(ctx context.Context, query func(context.Context, string, ...any) RowScanner, limit int) (CleanupSummary, error) {
	if query == nil || limit < 1 || limit > 10000 {
		return CleanupSummary{}, errors.New("audit cleanup requires a query executor and limit in 1..10000")
	}
	var removed int64
	var occurredFrom, occurredTo, expiredFrom, expiredTo sql.NullTime
	err := query(ctx, `WITH removed AS (
  DELETE FROM audit_events WHERE (service,event_id) IN (
   SELECT service,event_id FROM audit_events WHERE expires_at <= CURRENT_TIMESTAMP
   ORDER BY expires_at,service,event_id LIMIT $1
  ) RETURNING occurred_at,expires_at
 ) SELECT count(*),min(occurred_at),max(occurred_at),min(expires_at),max(expires_at) FROM removed`, limit).
		Scan(&removed, &occurredFrom, &occurredTo, &expiredFrom, &expiredTo)
	if err != nil {
		return CleanupSummary{}, err
	}
	utc := func(value sql.NullTime) *time.Time {
		if !value.Valid {
			return nil
		}
		t := value.Time.UTC()
		return &t
	}
	return CleanupSummary{Removed: removed, OccurredFrom: utc(occurredFrom), OccurredTo: utc(occurredTo), ExpiredFrom: utc(expiredFrom), ExpiredTo: utc(expiredTo)}, nil
}
