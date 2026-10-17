package durable

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPostgresMalformedEventBackoffAndSuccessor(t *testing.T) {
	cases := map[string]string{"type-error": `{"actor":"private-value"}`, "null": "null"}
	for _, kind := range []string{"schema", "identity", "service"} {
		e := fixture()
		e.ID = "malformed"
		e.OccurredAt = e.OccurredAt.Add(-time.Hour)
		switch kind {
		case "schema":
			e.SchemaVersion = 2
		case "identity":
			e.ID = "other-event"
		case "service":
			e.Service = "other-service"
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		cases[kind] = string(raw)
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) { testMalformedEventRecovery(t, payload) })
	}
}

func testMalformedEventRecovery(t *testing.T, payload string) {
	db := testDB(t)
	event := fixture()
	persist(t, db, event)
	var decoded Event
	_ = json.Unmarshal([]byte(payload), &decoded)
	occurred, expires := event.OccurredAt.Add(-time.Hour), event.ExpiresAt()
	if !decoded.OccurredAt.IsZero() {
		occurred, expires = decoded.OccurredAt, decoded.ExpiresAt()
	}
	digest := sha256.Sum256([]byte(payload))
	if _, err := db.Exec(`INSERT INTO audit_events(service,event_id,payload,content_hash,occurred_at,expires_at)
 VALUES($1,'malformed',$4::jsonb,$5,$2,$3)`, event.Service, occurred, expires, payload, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	var originalPayload, originalHash string
	var originalExpiry time.Time
	if err := db.QueryRow("SELECT payload::text,content_hash,expires_at FROM audit_events WHERE event_id='malformed'").Scan(&originalPayload, &originalHash, &originalExpiry); err != nil {
		t.Fatal(err)
	}
	sent := []string{}
	sender := func(_ context.Context, e Event) (Disposition, error) { sent = append(sent, e.ID); return Accepted, nil }
	attempted, err := ExportOne(context.Background(), db, sender)
	if !attempted || err == nil {
		t.Fatalf("malformed attempt=%v err=%v", attempted, err)
	}
	if strings.Contains(err.Error(), "private-value") {
		t.Fatal("private payload exposed in error")
	}
	var attempts int
	var ack sql.NullTime
	var delay float64
	if err := db.QueryRow("SELECT attempts,acknowledged_at,extract(epoch FROM next_attempt_at-clock_timestamp()) FROM audit_delivery WHERE event_id='malformed'").Scan(&attempts, &ack, &delay); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || ack.Valid || delay <= 0 || delay > 1 {
		t.Fatalf("malformed retry attempts=%d ack=%v remaining=%f", attempts, ack.Valid, delay)
	}
	if worked, err := ExportOne(context.Background(), db, sender); !worked || err != nil {
		t.Fatalf("valid successor: %v %v", worked, err)
	}
	if len(sent) != 1 || sent[0] != event.ID {
		t.Fatalf("sent=%v", sent)
	}
	var retainedPayload, hash string
	var expiry time.Time
	if err := db.QueryRow("SELECT payload::text,content_hash,expires_at FROM audit_events WHERE event_id='malformed'").Scan(&retainedPayload, &hash, &expiry); err != nil {
		t.Fatal(err)
	}
	if retainedPayload != originalPayload || hash != originalHash || !expiry.Equal(originalExpiry) {
		t.Fatal("malformed event changed")
	}
	if _, err := db.Exec("UPDATE audit_delivery SET next_attempt_at=now(),attempts=9 WHERE event_id='malformed'"); err != nil {
		t.Fatal(err)
	}
	if worked, err := ExportOne(context.Background(), db, sender); !worked || err == nil {
		t.Fatal("malformed retry must remain unsuccessful")
	}
	if err := db.QueryRow("SELECT attempts,extract(epoch FROM next_attempt_at-clock_timestamp()) FROM audit_delivery WHERE event_id='malformed'").Scan(&attempts, &delay); err != nil {
		t.Fatal(err)
	}
	if attempts != 10 || delay < 510 || delay > 512 || len(sent) != 1 {
		t.Fatalf("bounded retry attempts=%d delay=%f sent=%v", attempts, delay, sent)
	}
}

func TestPostgresAlteredEventBackoff(t *testing.T) {
	for _, kind := range []string{"actor", "payload-time", "stored-time", "stored-expiry", "hash"} {
		t.Run(kind, func(t *testing.T) {
			db := testDB(t)
			original := fixture()
			original.ID = "altered"
			original.OccurredAt = original.OccurredAt.Add(-time.Hour)
			persist(t, db, original)
			successor := fixture()
			persist(t, db, successor)
			query := ""
			switch kind {
			case "actor":
				query = `UPDATE audit_events SET payload=jsonb_set(payload,'{actor,id}','"different"') WHERE event_id='altered'`
			case "payload-time":
				query = `UPDATE audit_events SET payload=jsonb_set(payload,'{occurred_at}',to_jsonb(to_char(occurred_at+interval '1 minute','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))) WHERE event_id='altered'`
			case "stored-time":
				query = `UPDATE audit_events SET occurred_at=occurred_at-interval '1 minute' WHERE event_id='altered'`
			case "stored-expiry":
				query = `UPDATE audit_events SET expires_at=expires_at+interval '1 day' WHERE event_id='altered'`
			case "hash":
				query = `UPDATE audit_events SET content_hash='bad' WHERE event_id='altered'`
			}
			if _, err := db.Exec(query); err != nil {
				t.Fatal(err)
			}
			sent := []string{}
			sender := func(_ context.Context, e Event) (Disposition, error) { sent = append(sent, e.ID); return Accepted, nil }
			if worked, err := ExportOne(context.Background(), db, sender); !worked || err == nil || len(sent) != 0 {
				t.Fatalf("altered record dispatched: worked=%v err=%v sent=%v", worked, err, sent)
			}
			var attempts int
			if err := db.QueryRow("SELECT attempts FROM audit_delivery WHERE event_id='altered'").Scan(&attempts); err != nil || attempts != 1 {
				t.Fatalf("retry attempts=%d err=%v", attempts, err)
			}
			if worked, err := ExportOne(context.Background(), db, sender); !worked || err != nil || len(sent) != 1 || sent[0] != successor.ID {
				t.Fatalf("successor worked=%v err=%v sent=%v", worked, err, sent)
			}
		})
	}
}

func TestPostgresExportTimestampPrecision(t *testing.T) {
	for _, nanos := range []int{123456499, 123456500, 123456999} {
		db := testDB(t)
		event := fixture()
		now := time.Now().UTC()
		event.OccurredAt = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, nanos, time.UTC)
		persist(t, db, event)
		calls := 0
		if worked, err := ExportOne(context.Background(), db, func(_ context.Context, sent Event) (Disposition, error) {
			calls++
			if !sent.OccurredAt.Equal(event.OccurredAt) || !sent.ExpiresAt().Equal(event.ExpiresAt()) {
				t.Error("original nanosecond precision changed")
			}
			return Accepted, nil
		}); !worked || err != nil || calls != 1 {
			t.Fatalf("nanos=%d worked=%v err=%v calls=%d", nanos, worked, err, calls)
		}
	}
}
