// Package audit implements the etamong-lab cross-app logging convention:
// one request id (`ref`) joins one access line, zero-or-more audit lines, and any
// httperr error line — across services, on the same Grafana dashboards.
//
// Component coverage for the LLM Prompt Handling Standard:
//
//   - 1 access + audit log lines: RequestIDMiddleware, AccessLogMiddleware, Line
//   - 2 anonymized prompt storage: AnonID, MaskPII, embedded migration
//   - 4 (partial) prompt audit metric helpers
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Config tunes app-wide identity for log records.
type Config struct {
	// App tags every audit line so a single Grafana query separates services.
	App string
	// Salt keys AnonID. If empty, falls back to DATABASE_URL, then to a process-
	// lifetime random key (logged once). Set explicitly in prod for stable hashes
	// across replica restarts.
	Salt string
	// Output is the writer for both access and audit JSON lines. Defaults to
	// os.Stdout, which Promtail tails into Loki.
	Output io.Writer
}

var (
	cfg     Config
	cfgOnce sync.Once
	logger  *slog.Logger
)

// Init configures the package once. Subsequent calls are no-ops; tests may use
// reset internally. Safe to call zero times — defaults apply lazily.
func Init(c Config) {
	cfgOnce.Do(func() {
		if c.Output == nil {
			c.Output = os.Stdout
		}
		if c.Salt == "" {
			c.Salt = os.Getenv("DATABASE_URL")
		}
		if c.Salt == "" {
			var b [32]byte
			_, _ = rand.Read(b[:])
			c.Salt = hex.EncodeToString(b[:])
			log.Printf("audit: no Salt or DATABASE_URL — using a process-lifetime random key (hashes won't be stable across restarts)")
		}
		cfg = c
		logger = slog.New(slog.NewJSONHandler(cfg.Output, &slog.HandlerOptions{
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				if a.Key == slog.LevelKey {
					if lv, ok := a.Value.Any().(slog.Level); ok {
						a.Value = slog.StringValue(strings.ToLower(lv.String()))
					}
				}
				return a
			},
		}))
	})
}

func ensureInit() {
	if logger == nil {
		Init(Config{})
	}
}

// NewRef returns a fresh 8-hex correlation id, the standard etamong-lab ref shape.
func NewRef() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

const requestIDHeader = "X-Request-Id"

type ctxKey int

const reqIDKey ctxKey = 0

// ReqID returns the correlation id stored by RequestIDMiddleware, or "" if the
// middleware did not run for this request.
func ReqID(ctx context.Context) string {
	if id, ok := ctx.Value(reqIDKey).(string); ok {
		return id
	}
	return ""
}

// RequestIDMiddleware mints one correlation id per request (reusing an inbound
// X-Request-Id when present), stashes it in the context, and echoes it on the
// response. Install outermost so AccessLogMiddleware and any audit/error lines
// pick up the same ref.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = NewRef()
		}
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reqIDKey, id)))
	})
}

type accessLine struct {
	Time     string `json:"time"`
	Kind     string `json:"kind"`
	Ref      string `json:"ref,omitempty"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Duration int64  `json:"duration_ms"`
	IP       string `json:"ip"`
	User     string `json:"user,omitempty"`
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (w *statusCapture) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// AccessLogMiddleware writes one `kind:"access"` JSON line per request. Skips
// `/healthz` to keep Loki clean. Uses route template (`r.Pattern` on Go 1.22+)
// when available to keep cardinality finite.
func AccessLogMiddleware(next http.Handler) http.Handler {
	ensureInit()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sc := &statusCapture{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sc, r)
		path := r.URL.Path
		if r.Pattern != "" {
			path = r.Pattern
		}
		line := accessLine{
			Time:     start.UTC().Format(time.RFC3339),
			Kind:     "access",
			Ref:      ReqID(r.Context()),
			Method:   r.Method,
			Path:     path,
			Status:   sc.status,
			Duration: time.Since(start).Milliseconds(),
			IP:       ClientIP(r),
			User:     AuthUser(r),
		}
		b, err := json.Marshal(line)
		if err != nil {
			log.Printf("audit: access marshal error: %v", err)
			return
		}
		fmt.Fprintln(cfg.Output, string(b))
	})
}

// Line emits one planning#193 audit record. result is "ok" | "denied" | "error".
// detail carries app-specific fields and is logged verbatim — mask any PII
// before passing it in.
func Line(ref, actor, action, target, result string, detail map[string]any) {
	ensureInit()
	logger.LogAttrs(context.Background(), slog.LevelInfo, "audit",
		slog.String("app", cfg.App),
		slog.String("ref", ref),
		slog.String("actor", actor),
		slog.String("action", action),
		slog.String("target", target),
		slog.String("result", result),
		slog.Any("detail", detail),
	)
}

// ClientIP returns the first X-Forwarded-For entry, falling back to X-Real-Ip
// and then the socket peer. Trusts the cluster ingress to set these headers.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return xri
	}
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// AuthUser reads the identity our forward-auth (oauth2-proxy / Authentik) sets:
// preferred username first, then user, then email.
func AuthUser(r *http.Request) string {
	if u := r.Header.Get("X-Forwarded-Preferred-Username"); u != "" {
		return u
	}
	if u := r.Header.Get("X-Forwarded-User"); u != "" {
		return u
	}
	return r.Header.Get("X-Forwarded-Email")
}

// AnonID returns a keyed, truncated HMAC-SHA256 of an actor identifier so abuse
// can be correlated per-actor without persisting the raw value.
func AnonID(value string) string {
	if value == "" {
		return ""
	}
	ensureInit()
	mac := hmac.New(sha256.New, []byte(cfg.Salt))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}
