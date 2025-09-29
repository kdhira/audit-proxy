# audit-proxy

audit-proxy is a forward HTTP(S) proxy built for observability and policy enforcement of outbound API calls. The initial implementation focuses on transparent pass-through with structured JSON logs so teams can inspect traffic without modifying clients.

---

## Status

- **Version:** v0.1 (MVP skeleton)
- **Highlights:**
  - HTTP proxy handler with `CONNECT` tunneling
  - JSON Lines file logger with basic header redaction
  - CLI configuration via flags (`--addr`, `--log-file`, `--profiles`, etc.)
  - Profile registry with `generic` (always matches) and `openai` (hostname matcher with endpoint metadata)
  - Pluggable filter chain with a default header-block policy hook
  - MITM manager scaffolding that loads CA material (interception planned for v0.2)
  - Streaming tee utilities and smoke harness (`cmd/smokecheck`) for repeatable verification

Features such as active MITM interception, body capture, rich filtering, and UI tooling are planned but not yet implemented.

---

## Quick Start

```bash
go build ./cmd/audit-proxy
./audit-proxy --addr 127.0.0.1:8080 --log-file logs/audit.jsonl --profiles generic,openai
```

Point your tooling at the proxy:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
# Run your client commands as normal
```

Stop with `Ctrl+C`. Graceful shutdown waits up to 10 seconds for active connections to drain.

---

## Configuration Flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--addr` | `127.0.0.1:8080` | Listen address for the proxy. |
| `--log-file` | `logs/audit.jsonl` | Path to JSONL log file. Use `-` for stdout. |
| `--profiles` | `generic` | Comma-separated list of profile names to enable. |
| `--allow-hosts` | `*` | Comma-separated allowlist of upstream hosts (`*` permits all). |
| `--excerpt-limit` | `4096` | Maximum bytes captured for request/response excerpts (set `0` to disable body snippets). |
| `--mitm` | `false` | Enable CONNECT interception using supplied CA material. |
| `--mitm-ca`, `--mitm-key` | `` | Paths to MITM root certificate and key (required when `--mitm` is set). |
| `--mitm-disable-hosts` | `` | Comma-separated hosts that should never be intercepted even if MITM is enabled. |
| `--config` | `` | Optional path to YAML/JSON config file (values merge with CLI flags). |
| `--validate-config` | `false` | If set, validates configuration (including `--config`) and exits. |

Invalid flag combinations cause startup to fail with a descriptive message.

> **Note:** Enabling `--mitm` today only validates and loads the CA material; TLS interception and body capture will ship in v0.2.

---

## Logging

Each proxied request produces a single JSON entry:

```json
{
  "time": "2025-09-29T08:00:00Z",
  "id": "req-42",
  "conn": {
    "client_addr": "127.0.0.1",
    "target": "api.openai.com:443",
    "protocol": "https"
  },
  "request": {
    "method": "POST",
    "url": "https://api.openai.com/v1/responses",
    "headers": {
      "Authorization": "Bearer sk***23",
      "Content-Type": "application/json"
    },
    "content_length": 512
  },
  "response": {
    "status": 200,
    "headers": {
      "Content-Type": "application/json"
    },
    "content_length": 2048
  },
  "latency_ms": 420,
  "profile": "openai"
}
```

Sensitive headers (e.g., `Authorization`) are partially redacted before logging. When available, the proxy stores short `request_excerpt` / `response_excerpt` values (truncated according to `--excerpt-limit`) to aid debugging; buffers are pooled to keep the overhead low during streaming workloads.

---

## MITM Interception (Experimental)

Starting the proxy with `--mitm --mitm-ca <path> --mitm-key <path>` enables CONNECT interception:

- Per-host leaf certificates are minted from the supplied root CA.
- Certificates are cached for several hours to avoid regeneration on every CONNECT; restart to rotate early.
- TLS sessions are terminated inside the proxy, decrypted HTTP requests are forwarded using the existing transport, and body excerpts are captured.
- Audit entries include `"mitm":"enabled"` along with the usual profile metadata and excerpts.

This feature is an early milestone for v0.2. It currently focuses on HTTP/1.1 CONNECT tunnels and short excerpt capture; additional hardening (certificate caching, streaming optimisations, config knobs) is forthcoming.

---

## Profiles

Profiles add domain-specific awareness to log entries.

- `generic`: Always matches; emits no extra attributes.
- `openai`: Matches hosts containing `openai`; currently a stub for future annotations.

The proxy activates the first matching profile per request and records its name in the log entry. Future versions will enrich `attributes` with structured metadata.
Current OpenAI logs include endpoint, inferred operation, stream hints, masked organization/project identifiers, and response processing timing when available.

---

## Roadmap (High-Level)

1. MITM mode with per-host certificates and streaming-safe body capture.
2. Rich filter middleware with declarative policies and redaction helpers.
3. Profile enrichments for OpenAI endpoints and other SaaS APIs.
4. CLI/TUI log viewer with filtering and follow capabilities.
5. Pluggable storage backends (SQLite, S3) and metrics exporters.

See `SPEC_PLAN.md` for full architectural notes.

---

## Development

```bash
go test ./...
```

The codebase targets Go 1.25+. Please run `go fmt ./...` before sending patches.

### Configuration File

Instead of passing many flags, you can supply a YAML/JSON file with `--config`:

```yaml
addr: 0.0.0.0:8080
log_file: logs/audit.jsonl
profiles: [generic, openai]
excerpt_limit: 2048
mitm: true
mitm_ca: certs/ca.pem
mitm_key: certs/ca.key
mitm_disable_hosts: [api.openai.com]
filters:
  - type: header-block
    header: X-Audit-Block
    values: ["1", "true", "block"]
  - type: path-prefix-allow
    values: ["/public", "/status"]
```

CLI flags still take precedence for any values you provide explicitly.

### Smoke Test

Run the scripted smoke probe to exercise HTTP and CONNECT flows without background processes:

```bash
./scripts/smoke_proxy.sh
cat logs/smoke.jsonl
```

The log will contain two entries: one for a proxied HTTP request and one for the CONNECT tunnel established for HTTPS.
