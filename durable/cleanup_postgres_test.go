package durable

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func expiredCleanupFixture(t *testing.T, db *sql.DB, id string, occurred time.Time) Event {
	t.Helper()
	e := fixture()
	e.ID = id
	e.OccurredAt = occurred
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	_, err = db.Exec(`INSERT INTO audit_events(service,event_id,payload,content_hash,occurred_at,expires_at) VALUES($1,$2,$3::jsonb,$4,$5,$6)`, e.Service, e.ID, string(data), hex.EncodeToString(hash[:]), e.OccurredAt, e.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func cleanupFixtures(t *testing.T, db *sql.DB) []Event {
	t.Helper()
	dates := []time.Time{time.Date(2020, 2, 29, 10, 20, 30, 0, time.UTC), time.Date(2021, 6, 15, 4, 5, 6, 0, time.UTC), time.Date(2022, 1, 2, 3, 4, 5, 0, time.UTC)}
	events := []Event{}
	for i, at := range dates {
		events = append(events, expiredCleanupFixture(t, db, string(rune('a'+i)), at))
	}
	persist(t, db, fixture())
	return events
}

func assertCleanupRanges(t *testing.T, s CleanupSummary, n int64, from, to Event) {
	t.Helper()
	if s.Removed != n || s.OccurredFrom == nil || s.OccurredTo == nil || s.ExpiredFrom == nil || s.ExpiredTo == nil {
		t.Fatalf("missing cleanup summary: %+v", s)
	}
	for _, pair := range []struct {
		got  *time.Time
		want time.Time
	}{{s.OccurredFrom, from.OccurredAt}, {s.OccurredTo, to.OccurredAt}, {s.ExpiredFrom, from.ExpiresAt()}, {s.ExpiredTo, to.ExpiresAt()}} {
		if !pair.got.Equal(pair.want) || pair.got.Location() != time.UTC {
			t.Fatalf("range %s, want UTC %s", pair.got, pair.want)
		}
	}
}

func TestPostgresCleanupSummaryBoundsAndEmpty(t *testing.T) {
	db := testDB(t)
	events := cleanupFixtures(t, db)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	summary, err := purgeOnTx(ctx, tx, 2)
	if err != nil {
		t.Fatal(err)
	}
	assertCleanupRanges(t, summary, 2, events[0], events[1])
	if count(t, db, "audit_events") != 4 || count(t, db, "audit_delivery") != 4 {
		t.Fatal("cleanup committed the caller transaction")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "audit_events") != 2 || count(t, db, "audit_delivery") != 2 {
		t.Fatal("cleanup exceeded its batch or left delivery state")
	}
	if n, err := PurgeExpired(ctx, db, 100); err != nil || n != 1 {
		t.Fatalf("legacy count API: %d %v", n, err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	empty, err := purgeOnTx(ctx, tx, 1)
	if err != nil || empty != (CleanupSummary{}) {
		t.Fatalf("empty cleanup retained stale ranges: %+v %v", empty, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "audit_events") != 1 || count(t, db, "audit_delivery") != 1 {
		t.Fatal("cleanup removed unexpired/unacknowledged event")
	}
}

func TestPostgresCleanupOutcomeFailureRollsBackPurge(t *testing.T) {
	db := testDB(t)
	cleanupFixtures(t, db)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	summary, err := purgeOnTx(ctx, tx, 100)
	if err != nil || summary.Removed != 3 {
		t.Fatalf("cleanup: %+v %v", summary, err)
	}
	if err := Record(ctx, tx, fixture()); err == nil {
		t.Fatal("duplicate cleanup outcome was accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "audit_events") != 4 || count(t, db, "audit_delivery") != 4 {
		t.Fatal("failed cleanup audit left purged history")
	}
}

func TestPostgresCleanupOutcomeCommitsWithPurge(t *testing.T) {
	db := testDB(t)
	events := cleanupFixtures(t, db)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	summary, err := purgeOnTx(ctx, tx, 100)
	if err != nil {
		t.Fatal(err)
	}
	assertCleanupRanges(t, summary, 3, events[0], events[2])
	outcome := fixture()
	outcome.ID = "cleanup-outcome"
	outcome.Action = "audit.retention.purge"
	outcome.TargetType = "audit-history"
	outcome.TargetID = "expired-records"
	outcome.Changes = []Change{{Field: "removed", After: "3"}, {Field: "occurred_from", After: summary.OccurredFrom.Format(time.RFC3339Nano)}, {Field: "occurred_to", After: summary.OccurredTo.Format(time.RFC3339Nano)}, {Field: "expired_from", After: summary.ExpiredFrom.Format(time.RFC3339Nano)}, {Field: "expired_to", After: summary.ExpiredTo.Format(time.RFC3339Nano)}}
	if err := Record(ctx, tx, outcome); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "audit_events") != 4 {
		t.Fatal("outcome committed before its transaction")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "audit_events") != 2 || count(t, db, "audit_delivery") != 2 {
		t.Fatal("outcome/purge commit mismatch")
	}
	var data []byte
	if err := db.QueryRow("SELECT payload FROM audit_events WHERE event_id=$1", outcome.ID).Scan(&data); err != nil {
		t.Fatal(err)
	}
	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Changes) != 5 || got.Changes[0].After != "3" {
		t.Fatalf("unsafe or missing cleanup outcome: %+v", got)
	}
}

func TestPostgresCleanupPurgeAdapterRollsBack(t *testing.T) {
	db := testDB(t)
	cleanupFixtures(t, db)
	var schema string
	if err := db.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("AUDIT_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	ctx := context.Background()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	summary, err := PurgeExpiredWith(ctx, func(ctx context.Context, statement string, args ...any) RowScanner {
		return tx.QueryRow(ctx, statement, args...)
	}, 1)
	if err != nil || summary.Removed != 1 {
		t.Fatalf("pgx summary: %+v %v", summary, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "audit_events") != 4 || count(t, db, "audit_delivery") != 4 {
		t.Fatal("pgx purge escaped caller rollback")
	}
}

func TestPostgresConcurrentCleanupReportsActualDeletion(t *testing.T) {
	db := testDB(t)
	events := cleanupFixtures(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	initial, err := purgeOnTx(ctx, first, 2)
	if err != nil {
		t.Fatal(err)
	}
	assertCleanupRanges(t, initial, 2, events[0], events[1])
	second, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback()
	var firstPID, secondPID int
	if err := first.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&firstPID); err != nil {
		t.Fatal(err)
	}
	if err := second.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&secondPID); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		summary CleanupSummary
		err     error
	}
	done := make(chan answer, 1)
	go func() { s, err := purgeOnTx(ctx, second, 2); done <- answer{s, err} }()
	blocked := false
	for !blocked && ctx.Err() == nil {
		if err := db.QueryRowContext(ctx, "SELECT $1::int=ANY(pg_blocking_pids($2::int))", firstPID, secondPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if !blocked {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !blocked {
		t.Fatal("concurrent cleanup did not contend on the selected rows")
	}
	if err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	later := <-done
	if later.err != nil {
		t.Fatal(later.err)
	}
	if later.summary.Removed == 0 && later.summary != (CleanupSummary{}) {
		t.Fatalf("no deletion reported ranges: %+v", later.summary)
	}
	if err := second.Commit(); err != nil {
		t.Fatal(err)
	}
	remaining := int64(count(t, db, "audit_events")) - 1
	if initial.Removed+later.summary.Removed+remaining != 3 {
		t.Fatalf("cleanup double-counted concurrent deletion: %d + %d + %d", initial.Removed, later.summary.Removed, remaining)
	}
}

func TestPostgresCancelledCleanupRetainsHistory(t *testing.T) {
	db := testDB(t)
	cleanupFixtures(t, db)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	summary, err := purgeOnTx(ctx, tx, 100)
	if !errors.Is(err, context.Canceled) || summary != (CleanupSummary{}) {
		t.Fatalf("cancelled cleanup returned success: %+v %v", summary, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "audit_events") != 4 || count(t, db, "audit_delivery") != 4 {
		t.Fatal("cancelled cleanup removed history")
	}
}
