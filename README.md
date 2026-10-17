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
5. `audit.MaskPII(s)` — redacts emails, phone, Korean RRN, Luhn-valid card
   numbers, and vendor/generic secrets (Bearer/sk-/JWT, GitHub/AWS/Slack
   tokens, Basic auth, `key=value`/`key: value` assignments) before
   persisting prompt text. Does not mask IP addresses — access/audit lines
   keep `ip` readable for security investigation, matching the `ip` field
   in the access log shape below.
6. `audit/migrations/0001_prompt_audit.sql` — embedded as `audit.Migrations`
   `embed.FS`. Apps run it through their own migration driver.
7. `durable` — typed two-year action records, PostgreSQL transaction-bound
   persistence and a retrying exporter. It is separate from `audit.Line`,
   which remains an operational log and does not guarantee retained history.

## Durable mutation audit

Install `durable.Schema` through the application's migration runner before using the writer.
It creates `audit_events` and separate `audit_delivery` state, with a trigger that enqueues each event in the same transaction.
The enqueue trigger targets `audit_delivery` in the event table's schema, regardless of temporary tables or the caller's search path.
For an existing installation, apply the updated `audit_enqueue_event` function definition in a new forward migration; do not edit an already-applied checksummed migration.
A dependency update alone does not replace a function installed from a copied migration.
Application writers need `USAGE` on the containing schema, insert/select access to retained events and `INSERT (service, event_id)` on `audit_delivery`, because the enqueue trigger runs with caller privileges.
Delivery workers need read access to events, select/update on delivery state, and access to the containing schema.
Cleanup workers need delete/select on events and access to the containing schema; cascading removal handles delivery state.
Avoid event-update grants and user-deletion cascades.

```go
import "github.com/etamong-playground/audit-go/durable"

func renameItem(ctx context.Context, db *sql.DB, itemID, newName string) error {
    eventID, err := durable.NewID()
    if err != nil {
        return err
    }
    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()
    var oldName string
    if err := tx.QueryRowContext(ctx, "SELECT name FROM items WHERE id = $1 FOR UPDATE", itemID).Scan(&oldName); err != nil {
        return err
    }
    if _, err := tx.ExecContext(ctx, "UPDATE items SET name = $1 WHERE id = $2", newName, itemID); err != nil {
        return err
    }
    event := durable.Event{
        SchemaVersion: 1, ID: eventID, OperationID: eventID,
        Service: "example", Environment: "production", OccurredAt: time.Now().UTC(),
        Actor: durable.Actor{ID: "maintenance-job", Type: "job"},
        Action: "item.rename", TargetType: "item", TargetID: itemID, Result: "ok",
        Changes: []durable.Change{{Field: "name", Before: oldName, After: newName}},
    }
    if err := durable.Record(ctx, tx, event); err != nil {
        return err
    }
    return tx.Commit()
}
```

For pgx, pass an executor on the **active business transaction**, not a pool:

```go
err := durable.RecordWith(ctx, func(ctx context.Context, statement string, args ...any) error {
    _, err := tx.Exec(ctx, statement, args...)
    return err
}, event)
```

The caller must propagate every recording error and roll back the business operation.
Middleware that writes after a successful handler cannot provide atomicity.
For sensitive reads, commit a separate access event before releasing protected data.
External side effects need a committed intent and a later verified outcome with the same operation ID.

Only put explicitly allowlisted, bounded fields in `Changes`.
Tokens, passwords, raw bodies and prompt/document content must never enter this two-year record.
`ActorID` requires a dedicated key of at least 32 bytes and an issuer/subject pair; store its key version in a user actor's `KeyID`.
Keep that key stable across services and restarts if cross-service correlation is required.

Run `durable.ExportOne(ctx, db, sender)` from an application-owned worker.
The sender authenticates to the receiver and returns `durable.Accepted` only after central durable commit, or `durable.Expired` for an event actually past expiration.
It must honor its context deadline of at most 10 seconds; the exporter reserves five seconds of its 15-second transaction budget for recording delivery state, including time spent acquiring a connection.
The receiver must deduplicate stable IDs within authenticated producer identity and reject conflicting payloads.
Transport, credentials and central query authorization belong to the consuming application; this package does not supply a collector or HTTP protocol.

Failed sends and malformed stored payloads retain the event and schedule exponential retry (1 to 512 seconds).
Decoded events must satisfy the event contract and match their stored service, event ID, occurrence, expiry and canonical content hash.
Malformed events are not sent; their delivery failure leaves the original content and expiration intact for repair while eligible later events can progress.
An interrupted transaction or lost acknowledgement can resend the same event, so receiver deduplication is required.
Exporters skip each other's locked delivery rows.
The worker must wait on errors or empty batches rather than busy-looping, and monitor pending age/bytes and database capacity.

Events expire two calendar years after UTC occurrence, clamping leap day to February 28.
Acknowledgement never deletes retained history or extends its expiry.
Schedule bounded `durable.PurgeExpired(ctx, db, limit)` batches daily, and apply the same expiry before serving restored data.
Backups need a separate documented, bounded recovery window.

For a cleanup outcome that commits with deletion, use `durable.PurgeExpiredWith` on the active transaction.
Its `CleanupSummary` contains the actual removed count and inclusive UTC occurrence/expiry ranges, with nil ranges for an empty batch.
Only counts and time ranges are returned; expired identifiers and payloads are excluded.
Concurrent jobs may overlap selected rows, so a zero count does not prove that no expired rows remain.
Schedule bounded batches with a job deadline and inspect expiry lag separately.

```go
func purgeAuditBatch(ctx context.Context, db *sql.DB) (durable.Event, error) {
    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        return durable.Event{}, err
    }
    defer tx.Rollback()
    summary, err := durable.PurgeExpiredWith(ctx,
        func(ctx context.Context, query string, args ...any) durable.RowScanner {
            return tx.QueryRowContext(ctx, query, args...)
        }, 100)
    if err != nil || summary.Removed == 0 {
        return durable.Event{}, err
    }
    id, err := durable.NewID()
    if err != nil {
        return durable.Event{}, err
    }
    event := durable.Event{
        SchemaVersion: 1, ID: id, OperationID: id,
        Service: "example", Environment: "production", OccurredAt: time.Now().UTC(),
        Actor: durable.Actor{ID: "retention-worker", Type: "job"},
        Action: "audit.retention.purge", TargetType: "audit-history",
        TargetID: "expired-records", Result: "ok",
        Changes: []durable.Change{
            {Field: "removed", After: strconv.FormatInt(summary.Removed, 10)},
            {Field: "occurred_from", After: summary.OccurredFrom.Format(time.RFC3339Nano)},
            {Field: "occurred_to", After: summary.OccurredTo.Format(time.RFC3339Nano)},
            {Field: "expired_from", After: summary.ExpiredFrom.Format(time.RFC3339Nano)},
            {Field: "expired_to", After: summary.ExpiredTo.Format(time.RFC3339Nano)},
        },
    }
    if err := durable.Record(ctx, tx, event); err != nil {
        return durable.Event{}, err
    }
    return event, tx.Commit()
}
```

The snippet uses `context`, `database/sql`, `strconv`, `time` and `durable` imports.
Resolve the service/environment and job identity from trusted application configuration.
The application owns commit-outcome confirmation.
The snippet returns the outcome event even if commit acknowledgement fails; confirm its exact retained content independently before retrying, since a commit error does not prove rollback.
To record the outcome, the cleanup role additionally needs the writer's event and enqueue insert grants; it still needs no event-update grant.
For pgx, the callback returns `tx.QueryRow(ctx, query, args...)` instead.

Event validation limits envelopes to 64 KiB and rejects already-expired or more than five-minutes-future occurrences at recording time.

Run PostgreSQL integration checks against a dedicated test database:

```sh
AUDIT_TEST_DATABASE_URL=postgres://user:password@localhost:5432/audit_test?sslmode=disable go test -race ./...
```

Tests create and remove isolated schemas; CI supplies PostgreSQL and runs these checks alongside the existing logging tests.
pgx is used only as the test driver; the durable package itself uses the standard library.

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
