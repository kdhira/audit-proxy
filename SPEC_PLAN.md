# audit-proxy — Project Specification & Build Plan

**Status:** Draft (v0.1)  
**Owner:** Kevin (kdhira)  
**Repo:** `github.com/kdhira/audit-proxy`  
**Language:** Go (per `go.mod`)  
**Target:** macOS/Linux for local dev; Linux for shared/team deployments

---

## 1) Vision & Problem Statement

**audit-proxy** is a developer‑friendly, transparent **forward HTTP(S) proxy** that captures, inspects, and (optionally) filters outbound API traffic. It is **generic by design**—useful for any HTTP API (e.g., OpenAI, Azure OpenAI, GitHub, Slack, Stripe). It will ship with **profiles/plugins** (e.g., an OpenAI profile) that know how to extract domain‑specific fields (prompts, completions, etc.) and provide extra redaction/analysis.

### Why this exists
- Teams need **observability** for prompts & responses without rewriting clients.
- Security wants **central control** to redact secrets and block risky traffic.
- Devs need **transparent streaming support** to avoid breaking SDKs/CLIs.
- Auditors want **structured logs** that are both human‑readable and machine‑parsable.

### Non‑goals (for MVP)
- Not a full reverse proxy or API gateway for *all* services.  
- No persistence beyond file logs (DB backends come later).  
- No UI beyond CLI/TUI viewer of logs.  
- No auto‑TLS termination to clients (proxy listens HTTP; CONNECT is used for TLS tunneling). MITM (TLS intercept) is opt‑in only.

---

## 2) High‑Level Requirements

### Functional
1. **Forward HTTP(S) proxy** with `CONNECT` tunneling.
2. **Transparent pass‑through** for latency and streaming semantics (no buffering that breaks SSE/chunked).
3. **Logging** of request/response metadata and (optionally) bodies, with **automatic redaction** of sensitive values (Bearer tokens, API keys).
4. **Profiles/Plugins** to parse domain fields (e.g., OpenAI `/v1/chat/completions`, `/v1/responses`, `/v1/completions`, `/v1/audio/transcriptions`).
5. **Filters (middleware)** to block/mutate requests/responses (MVP ships with stubs and a simple example).
6. **Actor identification** hook: if `Authorization` is a JWT, optionally extract claims (e.g., `sub`, `email`) for logs.
7. **File‑based log storage** (JSON Lines). Pluggable storage interface for future DBs/S3.
8. **Config via flags/env/config file**. Host allowlist (default `*`), optional MITM CA, logging controls.
9. **CLI/TUI** for local tail/inspect.

### Non‑Functional
- Minimal overhead; streaming preserved; back‑pressure respected.
- Safe by default: no plaintext secret logging; strong redaction.
- Testable and modular; clean internal package boundaries.
- Clear docs; sensible defaults; graceful errors.
- Deployable locally or as a shared service.

---

## 3) Architecture Overview

```
+-------------------+        CONNECT / HTTP         +-------------------------+
|  Client / SDKs    |  ───────────────────────────▶ |  audit-proxy (HTTP)     |
|  (OpenAI CLI,     |                               |                         |
|   Codex IDE, etc) | ◀───────────────────────────  |  - Proxy Handler        |
+-------------------+         Responses             |    * CONNECT tunnel     |
                                                    |    * HTTP handler       |
                                                    |  - RoundTripper (FW)    |
                                                    |  - Logger / Redactor    |
                                                    |  - Profiles / Filters   |
                                                    |  - (opt) MITM Engine    |
                                                    +------------┬------------+
                                                                 │
                                                                 │ HTTPS (TLS)
                                                                 ▼
                                                    +-------------------------+
                                                    |  Remote API (OpenAI,    |
                                                    |  Azure OpenAI, etc.)    |
                                                    +-------------------------+
```

### Modes
- **Pass‑through (default):** `CONNECT` creates a TCP tunnel; contents stay encrypted end‑to‑end. We log connect metadata only (host, timing, bytes).  
- **MITM (opt‑in):** Proxy presents per‑host certs from a local CA; decrypts HTTPS to parse and log bodies, and to enable filtering/mutation.

### Streaming
- For MITM/HTTP requests, we **tee** streams: forward bytes to client while concurrently appending to an in‑memory or file buffer for logging; flush frequently to preserve real‑time UX.

---

## 4) Components & Abstractions

### 4.1 Proxy Core
- `internal/proxy/server.go` — `http.Handler` that dispatches:
  - `CONNECT` → `tunnel.go` (pass‑through or MITM intercept).
  - Plain HTTP → `forward.Transport` path.
- `internal/proxy/tunnel.go` — raw TCP piping; optional MITM handshake + HTTP parsing.

### 4.2 Forwarder (Transport)
- `internal/forward/transport.go` — custom `http.RoundTripper` that:
  - Redacts and logs request (read body to buffer, replace body with new `io.NopCloser`).
  - Calls underlying `http.Transport` (connection pooling, timeouts).
  - Streams response; tees to client and logger.

```go
type LoggingTransport struct {
    Base   http.RoundTripper    // usually http.DefaultTransport
    Logger audit.Logger         // interface
    Chain  filters.Chain        // request/response middleware
    Prof   profiles.Registry    // profile matchers/extractors
}
```

### 4.3 Audit & Storage
- `internal/audit/logger.go` — interfaces + `LogRecord` schema.
- `internal/audit/file_logger.go` — JSONL append, size/age rotation (MVP simple).
- `internal/audit/redact.go` — patterns:
  - `Authorization: Bearer <token>` → `Bearer ***REDACTED***`
  - Strings like `sk-...` (OpenAI) → masked
  - Generic keys: `api_key`, `access_token`, `password` in JSON → masked

**LogRecord (conceptual):**
```json
{
  "time": "RFC3339",
  "id": "uuid",
  "conn": { "client_ip": "1.2.3.4", "target": "api.openai.com:443" },
  "actor": { "sub": "user@example.com", "source": "jwt" },
  "request": { "method": "POST", "url": "https://api.openai.com/v1/responses",
               "headers": { ...redacted... }, "body": { ...maybe redacted... } },
  "response": { "status": 200, "headers": { ... }, "body": { ... } },
  "latency_ms": 123,
  "bytes_in": 2048,
  "bytes_out": 8192,
  "profile": "openai",
  "notes": []
}
```

### 4.4 Profiles / Plugins
- `internal/profiles/registry.go` — registration & dispatch by host/path.
- `internal/profiles/generic/` — default extractors (method/path, content‑type, length).
- `internal/profiles/openai/` — matchers for:
  - `/v1/chat/completions`, `/v1/completions`, `/v1/responses`
  - `/v1/audio/transcriptions`, `/v1/embeddings`, `/v1/images/*`
- Extract structured fields (model, messages, tools, choices).
- Provide extra **redaction** (e.g., hide system prompts) via profile hooks.

**Profile interfaces:**
```go
type Matcher interface {
    Match(req *http.Request) (ok bool, tag string)
}

type Extractor interface {
    Extract(req *http.Request, resp *http.Response) (map[string]any, map[string]any, error)
}

type Profile struct {
    Name      string
    Matchers  []Matcher
    Extractor Extractor
    Redactor  func(map[string]any) map[string]any
}
```

### 4.5 Filters (Middleware)
- `internal/filters/chain.go` — ordered hooks:
```go
type RequestFilter interface {
    OnRequest(ctx context.Context, req *http.Request) error // return ErrBlock to stop
}
type ResponseFilter interface {
    OnResponse(ctx context.Context, req *http.Request, resp *http.Response) error
}
type Chain struct {
    Req  []RequestFilter
    Resp []ResponseFilter
}
```
- MVP example: `BlockSecretsFilter` (regex for obvious key patterns in outgoing bodies/headers).

### 4.6 Config
- `internal/config/config.go`
  - Flags: `--addr`, `--logfile`, `--log-format=json|text`, `--profiles=openai,generic`,
           `--allow-hosts=*`, `--mitm-ca-cert`, `--mitm-ca-key`,
           `--log-bodies[=true|false]`, `--max-body-log-bytes=1048576`,
           `--actor-from-jwt[=true|false]`, `--tui`, `--metrics-addr`
  - Env overrides: `AUDITPROXY_*`
  - Optional YAML: `--config=path.yaml` (values override defaults; flags override file).

**Sample YAML:**
```yaml
addr: "127.0.0.1:8080"
profiles: ["generic", "openai"]
allow_hosts: ["*"]
logfile: "logs/audit.jsonl"
log_format: "json"
log_bodies: true
max_body_log_bytes: 1048576
mitm:
  ca_cert: ""
  ca_key:  ""
actor_from_jwt: true
metrics_addr: "127.0.0.1:9090"
```

### 4.7 Observability
- **Metrics** (optional): expose Prometheus at `--metrics-addr` (`/metrics`)
  - `requests_total{host,method,profile,status}`
  - `bytes_in_total`, `bytes_out_total`, `streaming_active`
  - `filter_blocks_total{filter}`
- **Tracing** (future): OpenTelemetry spans for proxy/roundtrip.

### 4.8 CLI/TUI
- `audit-proxy` — run the proxy.
- `audit-proxy view <file>` — TUI viewer (follow, filter by host/profile/status).

---

## 5) Data Handling & Safety

- **Default‑deny sensitive fields** in logs; masks applied before write.
- **Body logging off** by default in pass‑through mode (can’t read encrypted). In MITM mode, `--log-bodies` opt‑in.
- **Host allowlist** to reduce risk of general proxy abuse.
- **No storage of Bearer tokens**; if actor extraction is enabled, decode JWT without persisting the token.

---

## 6) Error Handling & Edge Cases

- Timeouts on dial and TLS handshakes; configurable.
- If `CONNECT` dial fails → `502 Bad Gateway`.
- If filter blocks → `403 Forbidden` with JSON error: `{"error":"blocked by policy","filter":"BlockSecretsFilter"}`
- Streaming failures: half‑close and propagate error; log partial bytes.
- Large bodies: cap log size; note truncation.

---

## 7) Performance Notes

- Use pooled `http.Transport`; enable `DisableCompression=false` to preserve semantics.
- Minimize copies: `io.CopyBuffer` for streams; T‑ee only when logging bodies.
- Backpressure: do not buffer entire streams; flush writer on chunk boundaries.

---

## 8) Project Structure

```
cmd/audit-proxy/main.go

internal/
  proxy/
    server.go
    tunnel.go
    filters.go
  forward/
    transport.go
  audit/
    logger.go
    file_logger.go
    redact.go
  profiles/
    registry.go
    generic/
      generic.go
    openai/
      openai.go
  config/
    config.go
  ui/
    tui.go

README.md
SPEC_PLAN.md
```

---

## 9) Testing Strategy

### Unit Tests
- **redact.go** — table‑driven tests for header/body key masking (Bearer, `sk-`, `api_key`, etc.).
- **file_logger.go** — writes JSONL; rotation (if implemented in MVP); concurrency tests.
- **profiles/openai** — extraction from sample payloads; system‑prompt redaction.
- **filters** — block/allow paths; error mapping.
- **transport** — request/response capture with a stub RoundTripper.

### Integration Tests
- Start proxy on random port.
- **Pass‑through**: make HTTPS request to a local TLS echo server via `CONNECT`; assert bytes and connect metadata.
- **MITM**: generate ephemeral CA; client trusts it; assert decrypted HTTP seen by profile/extractor; verify streaming chunk forwarding and logged aggregation.
- **Filters**: send a request containing a fake secret; assert `403` and log.

### Fuzz/Load (later)
- Fuzz header parsing & redaction; k6/vegeta for sustained load; ensure no goroutine leaks.

---

## 10) Security Considerations

- Safeguard CA private key; recommend file perms and separate service user.
- Explicit warnings in docs about MITM implications.
- Optional basic‑auth on proxy itself for shared deployments (future).
- Logs may contain user data in MITM mode → recommend encryption at rest and restricted access.

---

## 11) Delivery Plan & Milestones

**v0.1 (MVP)**
- Forward proxy with CONNECT pass‑through
- JSONL file logger (metadata only in pass‑through)
- Config (flags/env/YAML)
- Profiles: generic; skeleton openai (matchers only)
- Filters: scaffold + example no‑op
- Basic unit tests; README + SPEC

**v0.2**
- MITM support (CA, per‑host certs)
- Enable body logging & tee for streaming
- OpenAI profile extractor + redaction
- TUI: `view` (follow, filter)
- Prometheus metrics

**v0.3**
- Rotation/compression of logs
- Actor extraction from JWT
- Basic DLP filter (regex packs)
- Host allowlist + optional proxy auth
- More integration tests

**v0.4+**
- Pluggable storage backends (SQLite/Postgres/S3)
- WASM/Go‑plugin profile loaders
- OpenTelemetry tracing
- Policy language (declarative filters)

---

## 12) Open Questions / Assumptions

- JWT verification: for actor extraction, do we verify signature or only decode?
- Policy authoring UX: inline JSON rules vs DSL vs Rego?
- CA management UX: integrate `mkcert`‑style helper?

---

## 13) Appendix

### Example CLI

```bash
# Run locally
audit-proxy --addr 127.0.0.1:8080 --logfile logs/audit.jsonl --profiles generic,openai

# Use from a client/session
export HTTPS_PROXY=http://127.0.0.1:8080
# run your CLI/SDK as normal
```

### Example Log (MITM + OpenAI profile, truncated)

```json
{"time":"2025-09-29T08:00:00Z","id":"a1b2","conn":{"client_ip":"127.0.0.1","target":"api.openai.com:443"},"actor":{"sub":"alice@example.com"},"request":{"method":"POST","url":"https://api.openai.com/v1/responses","headers":{"authorization":"Bearer ***REDACTED***","content-type":"application/json"},"body":{"model":"gpt-4.1","input":[{"role":"user","content":"Hello"}]}},"response":{"status":200,"body":{"id":"resp_...","output":[{"content":[{"type":"output_text","text":"Hi!"}]}]}},"latency_ms":420,"profile":"openai"}
```
