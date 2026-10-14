package durable

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Schema is run by the application's migration driver, outside business transactions.
//
//go:embed schema.sql
var Schema string

// InsertFunc executes the supplied statement on the caller's active transaction.
// Passing a pool or independent transaction violates mutation/audit atomicity.
type InsertFunc func(context.Context, string, ...any) error

// Record writes on tx without committing it. The caller must roll back on error.
func Record(ctx context.Context, tx *sql.Tx, event Event) error {
	if tx == nil {
		return errors.New("audit recording requires a transaction")
	}
	return RecordWith(ctx, func(ctx context.Context, query string, args ...any) error {
		_, err := tx.ExecContext(ctx, query, args...)
		return err
	}, event)
}

// RecordWith supports transaction executors such as pgx without a driver dependency.
// It never starts or commits a transaction. Errors must abort the business operation.
func RecordWith(ctx context.Context, insert InsertFunc, event Event) error {
	if insert == nil {
		return errors.New("audit recording requires a transaction executor")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if event.OccurredAt.After(time.Now().Add(5*time.Minute)) || !event.ExpiresAt().After(time.Now()) {
		return errors.New("audit occurrence is future-dated or already expired")
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	return insert(ctx, `INSERT INTO audit_events (service, event_id, payload, content_hash, occurred_at, expires_at)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6)`, event.Service, event.ID, string(data), hex.EncodeToString(hash[:]), event.OccurredAt, event.ExpiresAt())
}

type Disposition string

const (
	Accepted Disposition = "accepted"
	Expired  Disposition = "expired"
)

// Sender must return Accepted only after authenticated central durable commit.
// Expired is the receiver's explicit disposition for an already-expired event.
// Sender must honor cancellation and the supplied deadline.
type Sender func(context.Context, Event) (Disposition, error)

// ExportOne locks one durable delivery row until send/ack completes.
// A crash or lost acknowledgement leaves the row available for idempotent replay.
// Concurrent exporters skip locked rows. Send receives at most 10 seconds,
// leaving time in the transaction's 15-second deadline to save retry state.
func ExportOne(ctx context.Context, db *sql.DB, send Sender) (bool, error) {
	if db == nil || send == nil {
		return false, errors.New("audit export requires database and sender")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var service, id string
	var data []byte
	var attempts int
	err = tx.QueryRowContext(ctx, `SELECT e.service, e.event_id, e.payload, d.attempts
		FROM audit_delivery d JOIN audit_events e USING (service, event_id)
		WHERE d.acknowledged_at IS NULL AND d.next_attempt_at <= CURRENT_TIMESTAMP
		AND e.expires_at > CURRENT_TIMESTAMP
		ORDER BY e.occurred_at, e.event_id
		LIMIT 1 FOR UPDATE OF d SKIP LOCKED`).Scan(&service, &id, &data, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return true, fmt.Errorf("invalid stored audit event: %w", err)
	}
	deadline, _ := ctx.Deadline()
	sendDeadline := deadline.Add(-5 * time.Second)
	if latest := time.Now().Add(10 * time.Second); latest.Before(sendDeadline) {
		sendDeadline = latest
	}
	sendCtx, cancelSend := context.WithDeadline(ctx, sendDeadline)
	var disposition Disposition
	var sendErr error
	if sendCtx.Err() != nil {
		sendErr = sendCtx.Err()
	} else {
		disposition, sendErr = send(sendCtx, event)
	}
	cancelSend()
	if sendErr == nil && disposition != Accepted && disposition != Expired {
		sendErr = errors.New("invalid audit delivery acknowledgement")
	}
	if sendErr == nil && disposition == Expired && event.ExpiresAt().After(time.Now()) {
		sendErr = errors.New("receiver expired an unexpired audit event")
	}
	if sendErr != nil {
		delay := retryDelay(attempts)
		_, err = tx.ExecContext(ctx, `UPDATE audit_delivery SET attempts = attempts + 1,
			next_attempt_at = clock_timestamp() + $3 * INTERVAL '1 second'
			WHERE service = $1 AND event_id = $2`, service, id, int(delay.Seconds()))
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE audit_delivery SET acknowledged_at = CURRENT_TIMESTAMP,
			attempts = attempts + 1 WHERE service = $1 AND event_id = $2`, service, id)
	}
	if err != nil {
		return true, err
	}
	if err := tx.Commit(); err != nil {
		return true, err
	}
	return true, sendErr
}

func retryDelay(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	if attempts > 9 {
		attempts = 9
	}
	return time.Duration(1<<attempts) * time.Second
}

// PurgeExpired removes expired payloads and cascades their delivery state.
// Applications schedule bounded batches; unexpired events are never removed.
func PurgeExpired(ctx context.Context, db *sql.DB, limit int) (int64, error) {
	if db == nil || limit < 1 || limit > 10000 {
		return 0, errors.New("audit cleanup requires database and limit in 1..10000")
	}
	result, err := db.ExecContext(ctx, `DELETE FROM audit_events WHERE (service, event_id) IN (
		SELECT service, event_id FROM audit_events WHERE expires_at <= CURRENT_TIMESTAMP
		ORDER BY expires_at LIMIT $1)`, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
