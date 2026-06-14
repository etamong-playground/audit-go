package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func resetForTest(out *bytes.Buffer) {
	cfgOnce = sync.Once{}
	logger = nil
	cfg = Config{}
	Init(Config{App: "testapp", Salt: "test-salt", Output: out})
}

func TestRequestIDMiddleware_Mints(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(&buf)

	var got string
	h := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ReqID(r.Context())
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)

	if len(got) != 8 {
		t.Fatalf("minted ref %q is not 8 hex", got)
	}
	if echo := rec.Header().Get("X-Request-Id"); echo != got {
		t.Fatalf("X-Request-Id %q != ctx %q", echo, got)
	}
}

func TestRequestIDMiddleware_PassesThrough(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(&buf)

	var got string
	h := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ReqID(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Request-Id", "abcdef12")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "abcdef12" {
		t.Fatalf("inbound ref dropped: got %q", got)
	}
}

func TestReqID_NoMiddleware(t *testing.T) {
	if got := ReqID(context.Background()); got != "" {
		t.Fatalf("ReqID without middleware = %q, want empty", got)
	}
}

func TestAnonID_Stable(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(&buf)
	a := AnonID("to.jooholee@gmail.com")
	b := AnonID("to.jooholee@gmail.com")
	if a != b {
		t.Fatalf("AnonID not stable: %s vs %s", a, b)
	}
	if len(a) != 16 {
		t.Fatalf("AnonID len %d, want 16", len(a))
	}
	if AnonID("") != "" {
		t.Fatal("AnonID empty input should return empty")
	}
}

func TestMaskPII(t *testing.T) {
	cases := []struct {
		in, must string
	}{
		{"contact me at to.jooholee@gmail.com please", "[redacted]"},
		{"call 010-1234-5678", "[redacted]"},
		{"rrn 900101-1234567 ok?", "[redacted]"},
		{"my key is sk-abcdef0123456789xyz", "[redacted]"},
		{"Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi", "[redacted]"},
	}
	for _, c := range cases {
		got := MaskPII(c.in)
		if !strings.Contains(got, c.must) {
			t.Errorf("MaskPII(%q) = %q, missing %q", c.in, got, c.must)
		}
	}
}

func TestAccessLog_Emit(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(&buf)

	h := RequestIDMiddleware(AccessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/x", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
	req.Header.Set("X-Forwarded-Email", "to.jooholee@gmail.com")
	h.ServeHTTP(httptest.NewRecorder(), req)

	line := buf.String()
	if !strings.Contains(line, `"kind":"access"`) {
		t.Fatalf("no access kind: %s", line)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &rec); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, line)
	}
	if rec["status"].(float64) != float64(http.StatusTeapot) {
		t.Errorf("status=%v", rec["status"])
	}
	if rec["ip"] != "203.0.113.1" {
		t.Errorf("ip=%v want 203.0.113.1", rec["ip"])
	}
	if rec["user"] != "to.jooholee@gmail.com" {
		t.Errorf("user=%v", rec["user"])
	}
	if ref, _ := rec["ref"].(string); len(ref) != 8 {
		t.Errorf("ref=%v, want 8-hex", rec["ref"])
	}
}

func TestAccessLog_SkipsHealthz(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(&buf)
	h := AccessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if buf.Len() != 0 {
		t.Fatalf("healthz logged: %s", buf.String())
	}
}

func TestAuditLine(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(&buf)
	Line("abcdef12", "to.jooholee@gmail.com", "prompt.generate", "diagram", "ok",
		map[string]any{"llm_model": "qwen3:4b", "duration_ms": 812})

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "audit" {
		t.Errorf("msg=%v", rec["msg"])
	}
	if rec["app"] != "testapp" {
		t.Errorf("app=%v", rec["app"])
	}
	if rec["ref"] != "abcdef12" {
		t.Errorf("ref=%v", rec["ref"])
	}
	if rec["level"] != "info" {
		t.Errorf("level=%v (want lowercased)", rec["level"])
	}
}

func TestMigrationsEmbedded(t *testing.T) {
	b, err := Migrations.ReadFile("migrations/0001_prompt_audit.sql")
	if err != nil {
		t.Fatalf("embed read: %v", err)
	}
	if !bytes.Contains(b, []byte("prompt_audit")) || !bytes.Contains(b, []byte("system_prompts")) {
		t.Fatal("migration missing expected tables")
	}
}
