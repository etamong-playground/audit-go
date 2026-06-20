# audit-go

> **About** — One of several small shared libraries used across a personal "fleet" of small apps (error handling · audit logging · encryption-at-rest · i18n · UI · …). Authored and maintained with [Claude Code](https://www.anthropic.com/claude-code) (Anthropic's agentic CLI). Each README documents the design rationale behind the library.
>
> **This is a public repository** — keep internal infrastructure details (hostnames, secret/Vault paths, private URLs, internal issue/MR references) out of code, comments, and commit messages.

The cross-app **access + audit + prompt-audit logging** convention for
Go HTTP services. One library implements the standard line shapes so every app's
records aggregate identically on shared Grafana dashboards (Loki backend).

It covers the structured access/audit log, anonymized prompt-audit storage, and a PII
mask. The system-prompt backoffice, per-app analyzer cron, and legal copy stay
app-local.

## Install

```sh
go get github.com/etamong-playground/audit-go
```

## What it gives you

1. `audit.RequestIDMiddleware` + `audit.ReqID(ctx)` — one 8-hex `ref` per request,
   echoed as `X-Request-Id`, joinable across access, audit and error lines.
   Install outermost.
2. `audit.AccessLogMiddleware` — emits one `kind:"access"` JSON line per request
   (skips `/healthz`).
3. `audit.Line(ref, actor, action, target, result, detail)` — emits one
   `msg:"audit"` line.
4. `audit.AnonID(value)` — keyed HMAC-SHA256 truncated to 16 hex; stable across
   the same deployment.
5. `audit.MaskPII(s)` — redacts emails, phone, bearer/sk- tokens, Korean RRN
   before persisting prompt text.
6. `audit/migrations/0001_prompt_audit.sql` — embedded as `audit.Migrations`
   `embed.FS`. Apps run it through their own migration driver.

## Minimal wiring

```go
import "github.com/etamong-playground/audit-go/audit"

func main() {
    audit.Init(audit.Config{App: "draw", Salt: os.Getenv("DRAW_HASH_SALT")})

    mux := http.NewServeMux()
    mux.HandleFunc("/api/...", handler)

    root := audit.RequestIDMiddleware(audit.AccessLogMiddleware(mux))
    http.ListenAndServe(":8080", root)
}

func handler(w http.ResponseWriter, r *http.Request) {
    ref := audit.ReqID(r.Context())
    audit.Line(ref, audit.AuthUser(r), "prompt.generate", "diagram", "ok",
        map[string]any{
            "prompt":      audit.MaskPII(prompt),
            "llm_model":   "qwen3:4b",
            "duration_ms": elapsed.Milliseconds(),
        })
}
```

## Line shapes

Access (`kind:"access"`):

```json
{"time":"…","kind":"access","ref":"3f9a1c0b","method":"POST","path":"/api/v1/generate","status":200,"duration_ms":812,"ip":"203.0.113.1","user":"alice@example.com"}
```

Audit (`msg:"audit"`):

```json
{"time":"…","level":"info","msg":"audit","app":"draw","ref":"3f9a1c0b","actor":"alice@example.com","action":"prompt.generate","target":"diagram","result":"ok","detail":{"prompt":"…","llm_model":"qwen3:4b","duration_ms":812}}
```

`ref` is a parsed field, never a Loki stream label.

## Out of scope

- HTTP error response shaping → use
  [`httperr`](https://github.com/etamong-playground/httperr).
  Both libraries share the `X-Request-Id` correlation contract — install
  `audit.RequestIDMiddleware` first, then httperr's `Responder` reads
  `audit.ReqID(ctx)`.
- Crypto for secret-at-rest → see [`crypto-go`](https://github.com/etamong-playground/crypto-go).
- The system-prompt backoffice + daily analyzer cron are app-local (per-app
  admin UI, per-app namespace CronJob).

## Acknowledgements

No third-party runtime dependencies — Go standard library only.

## License

MIT — see [LICENSE](LICENSE).
