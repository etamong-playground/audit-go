package durable

import (
	"context"
	"testing"
)

func TestPostgresEnqueueIgnoresShadowDelivery(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "CREATE TEMP TABLE audit_delivery (LIKE audit_delivery INCLUDING ALL) ON COMMIT DROP"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO items VALUES (1, 'changed')"); err != nil {
		t.Fatal(err)
	}
	event := fixture()
	if err := Record(ctx, tx, event); err != nil {
		t.Fatal(err)
	}
	var shadowRows int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM pg_temp.audit_delivery").Scan(&shadowRows); err != nil {
		t.Fatal(err)
	}
	if shadowRows != 0 {
		t.Fatalf("temporary table received %d durable delivery rows", shadowRows)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"items", "audit_events", "audit_delivery"} {
		if got := count(t, db, table); got != 1 {
			t.Fatalf("%s has %d rows, want 1", table, got)
		}
	}
	var service, id string
	if err := db.QueryRow("SELECT service, event_id FROM audit_delivery").Scan(&service, &id); err != nil {
		t.Fatal(err)
	}
	if service != event.Service || id != event.ID {
		t.Fatalf("delivery identity = %s/%s, want %s/%s", service, id, event.Service, event.ID)
	}
}
