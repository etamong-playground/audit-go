package durable

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUDIT_TEST_DATABASE_URL is unset")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	schema := "audit_test_" + id
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(); admin.Exec("DROP SCHEMA " + schema + " CASCADE"); admin.Close() })
	if _, err := db.Exec(Schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(Schema); err != nil {
		t.Fatalf("migration rerun: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE items (id integer PRIMARY KEY, name text NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	return db
}

func persist(t *testing.T, db *sql.DB, event Event) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := Record(context.Background(), tx, event); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresAtomicRecording(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO items VALUES (1, 'first')"); err != nil {
		t.Fatal(err)
	}
	if err := Record(ctx, tx, fixture()); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "items") != 0 || count(t, db, "audit_events") != 0 {
		t.Fatal("uncommitted state visible")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "items") != 1 || count(t, db, "audit_events") != 1 || count(t, db, "audit_delivery") != 1 {
		t.Fatal("mutation, event and delivery did not commit together")
	}
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO items VALUES (2, 'second')"); err != nil {
		t.Fatal(err)
	}
	e := fixture()
	e.ID = "event-2"
	if err := Record(ctx, tx, e); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "items") != 1 || count(t, db, "audit_events") != 1 {
		t.Fatal("rollback retained success state")
	}

	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO items VALUES (3, 'third')"); err != nil {
		t.Fatal(err)
	}
	if err := Record(ctx, tx, fixture()); err == nil {
		t.Fatal("duplicate event insert succeeded")
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("failed audit allowed business commit")
	}
	if count(t, db, "items") != 1 {
		t.Fatal("audit failure left a business mutation")
	}
}

func TestPostgresReplayAfterLostAcknowledgement(t *testing.T) {
	db := testDB(t)
	e := fixture()
	persist(t, db, e)
	seen := make(map[string]Event)
	calls := 0
	send := func(_ context.Context, got Event) (Disposition, error) {
		calls++
		seen[got.ID] = got
		if calls == 1 {
			return "", errors.New("acknowledgement lost after receiver commit")
		}
		return Accepted, nil
	}
	if attempted, err := ExportOne(context.Background(), db, send); !attempted || err == nil {
		t.Fatal("lost acknowledgement was not retried")
	}
	var ack sql.NullTime
	if err := db.QueryRow("SELECT acknowledged_at FROM audit_delivery").Scan(&ack); err != nil || ack.Valid {
		t.Fatal("failed delivery was acknowledged")
	}
	if _, err := db.Exec("UPDATE audit_delivery SET next_attempt_at = CURRENT_TIMESTAMP"); err != nil {
		t.Fatal(err)
	}
	if attempted, err := ExportOne(context.Background(), db, send); !attempted || err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(seen) != 1 || calls != 2 || seen[e.ID].OperationID != e.OperationID || !seen[e.ID].ExpiresAt().Equal(e.ExpiresAt()) {
		t.Fatal("replay changed event identity or retention")
	}
	if attempted, err := ExportOne(context.Background(), db, send); attempted || err != nil {
		t.Fatal("acknowledged event redelivered")
	}
	if count(t, db, "audit_events") != 1 {
		t.Fatal("acknowledgement deleted retained history")
	}
}

func TestPostgresExporterCrashAndConcurrency(t *testing.T) {
	db := testDB(t)
	e := fixture()
	persist(t, db, e)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := ExportOne(ctx, db, func(context.Context, Event) (Disposition, error) { cancel(); return Accepted, nil }); err == nil {
		t.Fatal("cancelled transaction acknowledged delivery")
	}
	if attempted, err := ExportOne(context.Background(), db, func(context.Context, Event) (Disposition, error) { return Accepted, nil }); !attempted || err != nil {
		t.Fatalf("restart failed to replay: %v", err)
	}
	e.ID = "event-2"
	persist(t, db, e)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := ExportOne(context.Background(), db, func(context.Context, Event) (Disposition, error) { close(entered); <-release; return Accepted, nil })
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("exporter did not acquire row")
	}
	if attempted, err := ExportOne(context.Background(), db, func(context.Context, Event) (Disposition, error) {
		t.Error("locked event sent twice")
		return Accepted, nil
	}); attempted || err != nil {
		t.Error("concurrent exporter did not skip locked row")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPostgresRejectsInvalidAcknowledgements(t *testing.T) {
	db := testDB(t)
	persist(t, db, fixture())
	for _, disposition := range []Disposition{"", Expired} {
		_, err := ExportOne(context.Background(), db, func(context.Context, Event) (Disposition, error) { return disposition, nil })
		if err == nil {
			t.Fatal("invalid acknowledgement accepted")
		}
		if _, err := db.Exec("UPDATE audit_delivery SET next_attempt_at = CURRENT_TIMESTAMP"); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM audit_delivery WHERE acknowledged_at IS NOT NULL").Scan(&n); err != nil || n != 0 {
		t.Fatal("invalid ack consumed event")
	}
}

func TestPostgresFailureBackoffStartsAfterSend(t *testing.T) {
	db := testDB(t)
	persist(t, db, fixture())
	var failedAt time.Time
	_, err := ExportOne(context.Background(), db, func(context.Context, Event) (Disposition, error) {
		time.Sleep(1100 * time.Millisecond)
		failedAt = time.Now()
		return "", errors.New("receiver unavailable")
	})
	if err == nil {
		t.Fatal("failed send did not report error")
	}
	var attempts int
	var next time.Time
	if err := db.QueryRow("SELECT attempts, next_attempt_at FROM audit_delivery").Scan(&attempts, &next); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || next.Before(failedAt.Add(900*time.Millisecond)) {
		t.Fatalf("backoff was not measured from failure: attempts=%d failed=%s next=%s", attempts, failedAt, next)
	}
}

func TestPostgresSenderTimeoutPersistsBackoff(t *testing.T) {
	db := testDB(t)
	persist(t, db, fixture())
	var failedAt time.Time
	_, err := ExportOne(context.Background(), db, func(ctx context.Context, _ Event) (Disposition, error) {
		<-ctx.Done()
		failedAt = time.Now()
		return "", ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected sender deadline, got %v", err)
	}
	var attempts int
	var next time.Time
	if err := db.QueryRow("SELECT attempts, next_attempt_at FROM audit_delivery").Scan(&attempts, &next); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || next.Before(failedAt.Add(900*time.Millisecond)) {
		t.Fatalf("sender timeout lost backoff: attempts=%d next=%s", attempts, next)
	}
}

func TestPostgresRestrictedWriter(t *testing.T) {
	db := testDB(t)
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	role := "audit_writer_" + id
	if _, err := db.Exec("CREATE ROLE " + role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec("DROP OWNED BY " + role)
		db.Exec("DROP ROLE " + role)
	})
	var schema string
	if err := db.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT INSERT, SELECT ON audit_events TO " + role,
		"GRANT INSERT ON items TO " + role,
		"GRANT INSERT (service, event_id) ON audit_delivery TO " + role,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("SET LOCAL ROLE " + role); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO items VALUES (1, 'restricted')"); err != nil {
		t.Fatal(err)
	}
	if err := Record(context.Background(), tx, fixture()); err != nil {
		t.Fatalf("documented restricted writer cannot record: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "audit_delivery") != 1 {
		t.Fatal("restricted writer did not enqueue delivery")
	}
}

func TestPostgresRestrictedCleanup(t *testing.T) {
	db := testDB(t)
	e := fixture()
	persist(t, db, e)
	e.ID = "unexpired"
	persist(t, db, e)
	if _, err := db.Exec("UPDATE audit_events SET expires_at = clock_timestamp() - INTERVAL '1 second' WHERE event_id = 'event-1'"); err != nil {
		t.Fatal(err)
	}
	id, _ := NewID()
	role := "audit_cleanup_" + id
	if _, err := db.Exec("CREATE ROLE " + role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec("DROP OWNED BY " + role)
		db.Exec("DROP ROLE " + role)
	})
	var schema string
	if err := db.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("GRANT USAGE ON SCHEMA " + schema + " TO " + role); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("GRANT DELETE, SELECT ON audit_events TO " + role); err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("SET ROLE " + role); err != nil {
		t.Fatal(err)
	}
	defer db.Exec("RESET ROLE")
	if n, err := PurgeExpired(context.Background(), db, 100); err != nil || n != 1 {
		t.Fatalf("restricted cleanup: removed %d, err %v", n, err)
	}
	if count(t, db, "audit_events") != 1 {
		t.Fatal("restricted cleanup removed unexpired history")
	}
}

func TestPostgresSenderReserveAfterConnectionWait(t *testing.T) {
	db := testDB(t)
	persist(t, db, fixture())
	db.SetMaxOpenConns(1)
	blocked, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	go func() {
		time.Sleep(6 * time.Second)
		blocked.Close()
	}()
	_, err = ExportOne(context.Background(), db, func(ctx context.Context, _ Event) (Disposition, error) {
		deadline, _ := ctx.Deadline()
		if time.Until(deadline) > 5*time.Second {
			t.Error("connection wait consumed the retry persistence reserve")
		}
		<-ctx.Done()
		return "", ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("sender deadline: %v", err)
	}
	var attempts int
	if err := db.QueryRow("SELECT attempts FROM audit_delivery").Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("contended send did not persist retry: attempts=%d err=%v", attempts, err)
	}
}

func TestPostgresRetentionCleanup(t *testing.T) {
	db := testDB(t)
	for i := 0; i < 3; i++ {
		e := fixture()
		e.ID = fmt.Sprint(i)
		persist(t, db, e)
	}
	if _, err := db.Exec("UPDATE audit_events SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' WHERE event_id IN ('0', '1')"); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	if _, err := ExportOne(context.Background(), db, func(_ context.Context, e Event) (Disposition, error) {
		ids = append(ids, e.ID)
		return Accepted, nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "2" {
		t.Fatal("expired event was exported")
	}
	if n, err := PurgeExpired(context.Background(), db, 1); err != nil || n != 1 {
		t.Fatalf("bounded cleanup: %d, %v", n, err)
	}
	if n, err := PurgeExpired(context.Background(), db, 100); err != nil || n != 1 {
		t.Fatalf("remaining cleanup: %d, %v", n, err)
	}
	if count(t, db, "audit_events") != 1 || count(t, db, "audit_delivery") != 1 {
		t.Fatal("cleanup removed unexpired event or retained orphan delivery")
	}
}
