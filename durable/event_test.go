package durable

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func fixture() Event {
	return Event{
		SchemaVersion: 1, ID: "event-1", OperationID: "operation-1",
		Service: "example", Environment: "test", OccurredAt: time.Now().UTC(),
		Actor: Actor{ID: "system", Type: "job"}, Action: "item.update",
		TargetType: "item", TargetID: "42", Result: "ok",
		Changes: []Change{{Field: "name", Before: "old", After: "new"}},
	}
}

func TestCalendarRetention(t *testing.T) {
	cases := []struct{ occurrence, expiry string }{
		{"2024-02-29T12:34:56Z", "2026-02-28T12:34:56Z"},
		{"2025-10-14T23:59:59Z", "2027-10-14T23:59:59Z"},
		{"2026-01-01T01:00:00+09:00", "2027-12-31T16:00:00Z"},
	}
	for _, tc := range cases {
		when, err := time.Parse(time.RFC3339, tc.occurrence)
		if err != nil {
			t.Fatal(err)
		}
		if got := (Event{OccurredAt: when}).ExpiresAt().Format(time.RFC3339); got != tc.expiry {
			t.Fatalf("%s expires at %s, want %s", tc.occurrence, got, tc.expiry)
		}
	}
}

func TestActorIdentityBoundaries(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	a, err := ActorID(key, "ab", "c")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ActorID(key, "a", "bc")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("different issuer/subject pairs collide")
	}
	again, _ := ActorID(key, "ab", "c")
	if a != again {
		t.Fatal("identity changed with the same key and principal")
	}
	rotated, _ := ActorID(bytes.Repeat([]byte{8}, 32), "ab", "c")
	if a == rotated {
		t.Fatal("key rotation did not change identity")
	}
	if _, err := ActorID([]byte("short"), "ab", "c"); err == nil {
		t.Fatal("weak key accepted")
	}
}

func TestValidationRejectsInvalidEventsBeforeInsert(t *testing.T) {
	cases := map[string]func(*Event){
		"missing actor":       func(e *Event) { e.Actor.ID = "" },
		"missing key version": func(e *Event) { e.Actor.Type = "user" },
		"unknown result":      func(e *Event) { e.Result = "success" },
		"invalid UTF-8":       func(e *Event) { e.TargetID = string([]byte{255}) },
		"oversized payload":   func(e *Event) { e.Changes[0].After = strings.Repeat("x", MaxEventBytes) },
		"future occurrence":   func(e *Event) { e.OccurredAt = time.Now().Add(time.Hour) },
		"expired occurrence":  func(e *Event) { e.OccurredAt = time.Now().AddDate(-3, 0, 0) },
	}
	for name, invalidate := range cases {
		t.Run(name, func(t *testing.T) {
			e := fixture()
			invalidate(&e)
			called := false
			err := RecordWith(context.Background(), func(context.Context, string, ...any) error { called = true; return nil }, e)
			if err == nil || called {
				t.Fatal("invalid event reached persistence")
			}
		})
	}
}
