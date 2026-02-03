# Security

## Reporting a Vulnerability

If you believe you have found a security vulnerability, please report it privately. Do not open a public issue. You can report by opening an issue with a private report or by contacting the maintainers directly.

## Security Considerations

### Log Level HTTP Endpoint

- **Access control**: By default, the Level endpoint has no authentication and no IP restriction. **In production you must** set either `AllowedIPs` or `RequireAuth` (or both). Do not expose the Level endpoint to the public or untrusted networks; otherwise anyone can change the log level (e.g. to trace/debug, causing information disclosure and log flooding, or to disabled, reducing observability).
- **Trusted proxies**: When the app is behind a reverse proxy, set `TrustedProxies` to the proxy IPs (or CIDRs). If `TrustedProxies` is not set, proxy headers (`X-Forwarded-For`, `X-Real-IP`) are not trusted and the client IP is taken from `RemoteAddr` only. This prevents IP spoofing; without it, an attacker could forge headers to bypass `AllowedIPs`.
- **Request body limit**: The Level endpoint limits the request body size (default 4KB) to reduce DoS risk.

### Request Logging Middleware

- **Query and body**: `IncludeQuery` is true by default. URL query strings often contain sensitive parameters (e.g. `token`, `password`, `code`). Use `SensitiveQueryParams` (default list includes common names) to redact values in logs. For request body, `IncludeBody` is false by default; enabling it may log passwords or tokens—use only for non-sensitive paths or with additional safeguards.
- **Trusted proxies**: Set `TrustedProxies` when behind a reverse proxy so the logged "ip" field reflects the real client IP when appropriate.
- **Headers**: Sensitive headers (e.g. Authorization, Cookie) are redacted by default when `IncludeHeaders` is true.

### Request ID

- Request IDs are generated with a cryptographically secure RNG (via `github.com/google/uuid`) when using the default generator.

### Console format and sensitive fields

- In console format, the default field value formatter uses `%v`, which can expose details (e.g. error messages, types with `String()`). Avoid logging sensitive fields; see `logger.SensitiveFieldNames` for common names. Use a custom `FormatFieldValue` in `ConsoleWriterConfig` to mask values if needed.

## Supported Versions

Security updates are applied to the current major version. Upgrade to the latest patch/minor release to receive fixes.
