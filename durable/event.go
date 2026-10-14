package durable

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxEventBytes = 64 * 1024

type Actor struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	KeyID string `json:"key_id,omitempty"`
}

// Change contains only fields the producer explicitly permits in audit storage.
// Credential values and raw request, document or prompt bodies must be excluded.
type Change struct {
	Field  string `json:"field"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type Event struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"event_id"`
	OperationID   string    `json:"operation_id"`
	Service       string    `json:"service"`
	Environment   string    `json:"environment"`
	OccurredAt    time.Time `json:"occurred_at"`
	Actor         Actor     `json:"actor"`
	Initiator     *Actor    `json:"initiator,omitempty"`
	Action        string    `json:"action"`
	TargetType    string    `json:"target_type"`
	TargetID      string    `json:"target_id"`
	Result        string    `json:"result"`
	Ref           string    `json:"ref,omitempty"`
	ReasonCode    string    `json:"reason_code,omitempty"`
	Changes       []Change  `json:"changes,omitempty"`
}

func NewID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

// ActorID uses a dedicated audit key and unambiguous issuer/subject encoding.
// Keep keyID with the result; rotation intentionally changes correlation.
func ActorID(key []byte, issuer, subject string) (string, error) {
	if len(key) < 32 || issuer == "" || subject == "" {
		return "", errors.New("audit identity requires a 32-byte key, issuer and subject")
	}
	input, err := json.Marshal([]string{issuer, subject})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ExpiresAt returns two calendar years after occurrence, clamping leap day.
func (e Event) ExpiresAt() time.Time {
	t := e.OccurredAt.UTC()
	day := t.Day()
	if t.Month() == time.February && day == 29 {
		day = 28
	}
	return time.Date(t.Year()+2, t.Month(), day, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}

func (e Event) Validate() error {
	if e.SchemaVersion != 1 || e.OccurredAt.IsZero() {
		return errors.New("audit event requires schema version 1 and occurrence time")
	}
	for name, value := range map[string]string{
		"event_id": e.ID, "operation_id": e.OperationID, "service": e.Service,
		"environment": e.Environment, "actor.id": e.Actor.ID, "action": e.Action,
		"target_type": e.TargetType, "target_id": e.TargetID,
	} {
		if err := validText(name, value, true); err != nil {
			return err
		}
	}
	if err := validActor(e.Actor); err != nil {
		return err
	}
	if e.Initiator != nil {
		if err := validActor(*e.Initiator); err != nil {
			return err
		}
	}
	switch e.Result {
	case "ok", "denied", "error", "pending", "unknown":
	default:
		return errors.New("invalid audit result")
	}
	for name, value := range map[string]string{"ref": e.Ref, "reason_code": e.ReasonCode} {
		if err := validText(name, value, false); err != nil {
			return err
		}
	}
	if len(e.Changes) > 100 {
		return errors.New("too many audit changes")
	}
	for _, c := range e.Changes {
		if err := validText("change.field", c.Field, true); err != nil {
			return err
		}
		if !utf8.ValidString(c.Before) || !utf8.ValidString(c.After) {
			return errors.New("invalid UTF-8 in audit change")
		}
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(data) > MaxEventBytes {
		return errors.New("audit event exceeds 64 KiB")
	}
	return nil
}

func validActor(actor Actor) error {
	if err := validText("actor.id", actor.ID, true); err != nil {
		return err
	}
	if err := validText("actor.key_id", actor.KeyID, false); err != nil {
		return err
	}
	switch actor.Type {
	case "user":
		if actor.KeyID == "" {
			return errors.New("user audit actor requires key_id")
		}
	case "service", "job", "anonymous":
	default:
		return errors.New("invalid audit actor type")
	}
	return nil
}

func validText(name, value string, required bool) error {
	if !utf8.ValidString(value) || len(value) > 512 || strings.ContainsRune(value, 0) || (required && strings.TrimSpace(value) == "") {
		return fmt.Errorf("invalid audit %s", name)
	}
	return nil
}
