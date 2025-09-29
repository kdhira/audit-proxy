# audit-proxy

audit-proxy is a transparent HTTP/HTTPS proxy designed to audit, filter, and observe network traffic with a focus on security, privacy, and compliance. It acts as a man-in-the-middle (MITM) proxy, allowing inspection and modification of requests and responses in real-time.

---

## Features

- Transparent HTTP and HTTPS proxy with MITM capabilities
- Flexible configuration via JSON profiles and YAML filters
- Built-in filters for auditing, redacting sensitive data, and enforcing policies
- Observability hooks for logging and metrics
- Support for OpenAI API auditing and filtering
- Extensible middleware architecture
- Detailed logging with structured JSON output for easy analysis
- Lightweight and performant with minimal dependencies

---

## Quick Start

1. **Install**

   Download the latest release from the [GitHub releases page](https://github.com/kdhira/audit-proxy/releases).

2. **Run**

   ```bash
   ./audit-proxy --config config.json
   ```

3. **Configure**

   Edit `config.json` to specify proxy ports, profiles, and filters.

4. **Set your system or application to use the proxy**

   Configure your HTTP/HTTPS client or system proxy settings to point to `localhost:<proxy-port>`.

---

## MITM Mode

audit-proxy supports man-in-the-middle mode for HTTPS traffic by generating certificates on the fly. To enable MITM:

1. Generate a root CA certificate:

   ```bash
   ./audit-proxy --gen-ca > rootCA.pem
   ```

2. Install `rootCA.pem` in your system or browser trusted certificate store.

3. Enable MITM in your config:

   ```json
   {
     "mitm": true,
     "ca_cert_path": "rootCA.pem",
     "ca_key_path": "rootCA.key"
   }
   ```

This allows audit-proxy to decrypt and inspect HTTPS traffic securely.

---

## Configuration

audit-proxy uses a JSON configuration file to define:

- Proxy listening ports
- Profiles that define behavior and filters
- Logging options
- MITM settings

Example snippet:

```json
{
  "proxy_port": 8080,
  "mitm": true,
  "profiles": {
    "default": {
      "filters": ["audit", "redact"],
      "logging": {
        "level": "info",
        "format": "json"
      }
    }
  }
}
```

---

## Logging Schema

Logs are emitted in structured JSON format with the following fields:

- `timestamp`: ISO8601 timestamp of the event
- `level`: log level (info, warn, error, debug)
- `event`: event type (request, response, error, audit)
- `request_id`: unique ID per request
- `method`: HTTP method
- `url`: request URL
- `status`: HTTP status code (for responses)
- `duration_ms`: time taken to process request
- `message`: human-readable message
- `details`: additional metadata (headers, audit findings)

Example log entry:

```json
{
  "timestamp": "2024-06-01T12:00:00Z",
  "level": "info",
  "event": "request",
  "request_id": "abc123",
  "method": "POST",
  "url": "https://api.openai.com/v1/chat/completions",
  "message": "Request received"
}
```

---

## Profiles

Profiles define sets of filters and behaviors for different use cases.

### OpenAI Profile

The OpenAI profile is tailored for auditing and filtering OpenAI API requests and responses.

Features:

- Detects sensitive data in prompts and completions
- Redacts API keys and tokens
- Enforces usage policies
- Logs audit events with context

Example:

```json
{
  "profiles": {
    "openai": {
      "filters": ["openai-audit", "redact-api-keys"],
      "logging": {
        "level": "debug"
      }
    }
  }
}
```

---

## Filters (Middleware)

Filters are pluggable middleware components that inspect and modify traffic.

Common filters included:

- **audit**: Logs request and response metadata
- **redact**: Removes or masks sensitive headers and payload fields
- **openai-audit**: Specific auditing for OpenAI API traffic
- **rate-limit**: Enforces request rate limits per client
- **cors**: Adds or modifies CORS headers

Filters can be chained in profiles to customize behavior.

---

## Observability

audit-proxy exposes metrics and events to facilitate monitoring:

- **Metrics**: HTTP request counts, latencies, error rates
- **Events**: Audit findings, filter actions, security alerts
- **Logging**: Structured logs for integration with ELK, Splunk, or other systems

Metrics can be exposed via Prometheus endpoints if enabled in config.

---

## Development Guide

### Layout

- `cmd/` - main application entrypoint
- `pkg/` - core proxy and filter implementations
- `configs/` - example configuration files
- `tests/` - integration and unit tests

### Running Locally

Build and run:

```bash
go build -o audit-proxy ./cmd/audit-proxy
./audit-proxy --config configs/default.json
```

### Tests

Run tests with:

```bash
go test ./...
```

Integration tests require Docker for simulating proxy traffic.

### Code Style

- Follow Go idioms and formatting (`gofmt`)
- Use descriptive variable names and comments
- Maintain modular filter implementations

---

## Security Notes

- MITM requires installing a trusted root CA; keep private keys secure
- Audit logs may contain sensitive data; secure log storage is recommended
- Filters should be reviewed for performance and security impact
- Regularly update audit-proxy to incorporate security patches

---

## Roadmap

- Add support for WebSocket proxying and auditing
- Enhance filter DSL for custom user-defined rules
- Integrate with SIEM systems for real-time alerts
- Provide GUI for configuration and monitoring
- Support additional protocols beyond HTTP(S)

---

## FAQ

**Q: Can audit-proxy handle HTTP/2 traffic?**  
A: Yes, audit-proxy supports HTTP/2 proxying and MITM inspection.

**Q: How do I add custom filters?**  
A: Implement the filter interface in Go and register it in the configuration.

**Q: Is audit-proxy suitable for production use?**  
A: audit-proxy is designed for both development and production environments but should be tested and configured according to your security requirements.

**Q: How do I troubleshoot certificate errors in MITM mode?**  
A: Ensure the root CA certificate is correctly installed and trusted on the client device or browser.

---

For more information, please visit the [GitHub repository](https://github.com/kdhira/audit-proxy).
