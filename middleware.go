package logger

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// MiddlewareConfig configures the logging middleware.
type MiddlewareConfig struct {
	// Logger is the logger to use.
	// If nil, the default logger is used.
	Logger *Logger

	// SkipPaths is a list of paths to skip logging.
	// Useful for health check endpoints.
	SkipPaths []string

	// SkipFunc is a function to determine if logging should be skipped.
	// If it returns true, the request is not logged.
	SkipFunc func(r *http.Request) bool

	// LogLevel is the log level for successful requests (status < 400).
	// Default: InfoLevel
	LogLevel Level

	// WarnLevel is the log level for client errors (400-499).
	// Default: WarnLevel
	WarnLevel Level

	// ErrorLevel is the log level for server errors (500+).
	// Default: ErrorLevel
	ErrorLevel Level

	// IncludeRequestID adds request ID to the log and context.
	// Default: true
	IncludeRequestID bool

	// RequestIDHeader is the header to read/write request ID.
	// Default: "X-Request-ID"
	RequestIDHeader string

	// GenerateRequestID generates a new request ID if not present.
	// If nil, a UUID is generated.
	GenerateRequestID func() string

	// IncludeLatency includes request latency in logs.
	// Default: true
	IncludeLatency bool

	// IncludeHeaders includes request headers in logs.
	// Default: false
	IncludeHeaders bool

	// SensitiveHeaders is a list of header names to mask in logs.
	// Default: ["Authorization", "X-API-Key", "Cookie", "Set-Cookie"]
	SensitiveHeaders []string

	// IncludeQuery includes query parameters in logs.
	// Default: true
	IncludeQuery bool

	// SensitiveQueryParams is a list of query parameter names to redact (value
	// replaced with "***"). When empty, defaultSensitiveQueryParams is used.
	//
	// Use DisableQueryRedaction to turn redaction off. This used to be spelled
	// by passing nil rather than an empty slice -- a distinction that does not
	// survive a round trip through JSON or YAML, where an omitted field
	// unmarshals to nil, so deserialising a config silently disabled redaction.
	SensitiveQueryParams []string

	// DisableQueryRedaction logs query strings verbatim.
	DisableQueryRedaction bool

	// SensitiveBodyFields is a list of field names to redact inside a logged
	// request body. When empty, defaultSensitiveBodyFields is used.
	//
	// JSON and form-encoded bodies are redacted field by field; a body in any
	// other format is replaced wholesale, since there is no structure to
	// redact selectively.
	SensitiveBodyFields []string

	// DisableBodyRedaction logs request bodies verbatim.
	//
	// Only set this where bodies are known not to carry credentials. The
	// password in a JSON or form login request lives in the body, not in the
	// query string or the headers.
	DisableBodyRedaction bool

	// IncludeBody includes request body in logs. The body is redacted unless
	// DisableBodyRedaction is set; see SensitiveBodyFields.
	// Warning: This may log sensitive data.
	// Default: false
	IncludeBody bool

	// MaxBodySize is the maximum body size to log (in bytes).
	// Bodies larger than this are truncated.
	// Default: 1024
	MaxBodySize int

	// CustomFields adds custom fields to each log entry.
	CustomFields func(r *http.Request) map[string]interface{}

	// TrustedProxies is a list of proxy IPs (or CIDRs). When non-empty, X-Forwarded-For
	// and X-Real-IP are only used for the "ip" log field when the direct peer is in this list.
	// When empty (default), only RemoteAddr is used. Set this when behind a reverse proxy.
	TrustedProxies []string
}

// DefaultMiddlewareConfig returns the default middleware configuration.
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		LogLevel:         InfoLevel,
		WarnLevel:        WarnLevel,
		ErrorLevel:       ErrorLevel,
		IncludeRequestID: true,
		RequestIDHeader:  "X-Request-ID",
		IncludeLatency:   true,
		IncludeQuery:     true,
		MaxBodySize:      1024,
		SensitiveHeaders: []string{
			"Authorization",
			"X-API-Key",
			"X-Signature",
			"Cookie",
			"Set-Cookie",
		},
		SensitiveQueryParams: defaultSensitiveQueryParams,
	}
}

// defaultSensitiveQueryParams are query keys redacted in logs when SensitiveQueryParams is empty.
var defaultSensitiveQueryParams = []string{
	"password", "token", "code", "secret", "key", "api_key", "apikey",
	"access_token", "refresh_token", "session", "session_id",
}

// RedactQuery masks the values of sensitive query parameters. An empty
// sensitiveKeys means nothing is redacted; callers pass the default list when
// they want redaction.
//
// Exported so a framework adapter redacts by the same rule -- a log line that
// leaks a token on one framework and not the other is the worst kind of
// inconsistency.
func RedactQuery(rawQuery string, sensitiveKeys []string) string {
	if rawQuery == "" {
		return ""
	}
	if len(sensitiveKeys) == 0 {
		return rawQuery
	}
	keysMap := make(map[string]bool)
	for _, k := range sensitiveKeys {
		keysMap[strings.ToLower(strings.TrimSpace(k))] = true
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "[UNPARSEABLE QUERY REDACTED]"
	}
	var buf strings.Builder
	for k, v := range vals {
		keyLower := strings.ToLower(k)
		if keysMap[keyLower] {
			buf.WriteString(url.QueryEscape(k))
			buf.WriteString("=***&")
		} else {
			for _, vv := range v {
				buf.WriteString(url.QueryEscape(k))
				buf.WriteString("=")
				buf.WriteString(url.QueryEscape(vv))
				buf.WriteString("&")
			}
		}
	}
	s := buf.String()
	if len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// Normalized fills in every default the middleware relies on: the logger, the
// request-id header, the body-size cap, the three log levels and the
// sensitive-header list.
//
// Exported because a framework adapter must resolve a config exactly the way
// this package does. "What counts as sensitive" differing by framework would
// mean a token redacted on one and logged in clear on the other.
func (cfg MiddlewareConfig) Normalized() MiddlewareConfig {
	if cfg.Logger == nil {
		cfg.Logger = defaultLogger
	}
	if cfg.RequestIDHeader == "" {
		cfg.RequestIDHeader = "X-Request-ID"
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = 1024
	}

	// Apply default log levels if not set (zero value is DebugLevel).
	// All three at their zero value means "unset"; that avoids overwriting an
	// intentional DebugLevel.
	defaults := DefaultMiddlewareConfig()
	if cfg.LogLevel == DebugLevel && cfg.WarnLevel == DebugLevel && cfg.ErrorLevel == DebugLevel {
		cfg.LogLevel = defaults.LogLevel
		cfg.WarnLevel = defaults.WarnLevel
		cfg.ErrorLevel = defaults.ErrorLevel
	}

	if len(cfg.SensitiveHeaders) == 0 {
		cfg.SensitiveHeaders = []string{"Authorization", "X-API-Key", "X-Signature", "Cookie", "Set-Cookie"}
	}

	return cfg
}

// SensitiveBodyKeys returns the body field names to redact, falling back to the
// package defaults when none are configured.
func (cfg MiddlewareConfig) SensitiveBodyKeys() []string {
	if len(cfg.SensitiveBodyFields) == 0 {
		return defaultSensitiveBodyFields
	}
	return cfg.SensitiveBodyFields
}

// SensitiveQueryKeys returns the query keys to redact, or nil when redaction is
// switched off.
//
// An empty list means "use the defaults"; turning redaction off is spelled
// DisableQueryRedaction. Relying on nil-versus-empty did not survive a round
// trip through JSON or YAML, where an omitted field unmarshals to nil -- so
// deserialising a config silently disabled redaction.
func (cfg MiddlewareConfig) SensitiveQueryKeys() []string {
	if cfg.DisableQueryRedaction {
		return nil
	}
	if len(cfg.SensitiveQueryParams) == 0 {
		return defaultSensitiveQueryParams
	}
	return cfg.SensitiveQueryParams
}

// SkipPathSet is cfg.SkipPaths as a lookup set.
func (cfg MiddlewareConfig) SkipPathSet() map[string]bool {
	set := make(map[string]bool, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		set[p] = true
	}
	return set
}

// SensitiveHeaderSet is cfg.SensitiveHeaders lower-cased, as a lookup set.
func (cfg MiddlewareConfig) SensitiveHeaderSet() map[string]bool {
	set := make(map[string]bool, len(cfg.SensitiveHeaders))
	for _, h := range cfg.SensitiveHeaders {
		set[strings.ToLower(h)] = true
	}
	return set
}

// Middleware creates a standard net/http logging middleware.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	cfg = cfg.Normalized()
	skipPathMap := cfg.SkipPathSet()
	sensitiveHeaderMap := cfg.SensitiveHeaderSet()
	sensitiveBodyFields := cfg.SensitiveBodyKeys()
	sensitiveQueryKeys := cfg.SensitiveQueryKeys()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if path is in skip list
			if skipPathMap[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Skip if skip function returns true
			if cfg.SkipFunc != nil && cfg.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Handle request ID
			requestID := r.Header.Get(cfg.RequestIDHeader)
			if requestID == "" && cfg.IncludeRequestID {
				if cfg.GenerateRequestID != nil {
					requestID = cfg.GenerateRequestID()
				} else {
					requestID = NewRequestID()
				}
				r.Header.Set(cfg.RequestIDHeader, requestID)
			}

			// Set request ID in response header
			if cfg.IncludeRequestID && requestID != "" {
				w.Header().Set(cfg.RequestIDHeader, requestID)
			}

			// Add request ID to context
			if requestID != "" {
				r = r.WithContext(ContextWithRequestID(r.Context(), requestID))
			}

			// Add logger to context
			r = r.WithContext(ContextWithLogger(r.Context(), cfg.Logger))

			var requestBodyForLog []byte
			if cfg.IncludeBody && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) && r.Body != nil {
				// One byte past the limit, so truncation is detectable. Capping
				// the read at exactly MaxBodySize made a complete body of that
				// size indistinguishable from a truncated one.
				requestBodyForLog, _ = io.ReadAll(io.LimitReader(r.Body, int64(cfg.MaxBodySize)+1))
				r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(requestBodyForLog), r.Body))
			}

			// Wrap response writer to capture status
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			// Process request
			next.ServeHTTP(rw, r)

			// Calculate latency
			latency := time.Since(start)

			// Determine log level based on status code
			var logLevel Level
			switch {
			case rw.status >= 500:
				logLevel = cfg.ErrorLevel
			case rw.status >= 400:
				logLevel = cfg.WarnLevel
			default:
				logLevel = cfg.LogLevel
			}

			// Build log event
			zl := cfg.Logger.Zerolog()
			event := zl.WithLevel(logLevel.ToZerolog())

			// Add standard fields
			event = event.
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", rw.status).
				Str("ip", ClientIP(RequestSource(r), cfg.TrustedProxies)).
				Str("user_agent", r.UserAgent())

			// Add request ID
			if cfg.IncludeRequestID && requestID != "" {
				event = event.Str("request_id", requestID)
			}

			// Add latency
			if cfg.IncludeLatency {
				event = event.Dur("latency", latency)
			}

			// Add query parameters (with sensitive keys redacted)
			if cfg.IncludeQuery && r.URL.RawQuery != "" {
				event = event.Str("query", RedactQuery(r.URL.RawQuery, sensitiveQueryKeys))
			}

			// Add headers
			if cfg.IncludeHeaders {
				headers := make(map[string]string)
				for name, values := range r.Header {
					if sensitiveHeaderMap[strings.ToLower(name)] {
						headers[name] = "[REDACTED]"
					} else if len(values) > 0 {
						headers[name] = values[0]
					}
				}
				event = event.Interface("headers", headers)
			}

			// Add request body (net/http: from buffered peek)
			if cfg.IncludeBody && len(requestBodyForLog) > 0 {
				body := requestBodyForLog
				truncated := len(body) > cfg.MaxBodySize
				if truncated {
					body = body[:cfg.MaxBodySize]
				}
				logged := string(body)
				if !cfg.DisableBodyRedaction {
					logged = RedactBody(r.Header.Get("Content-Type"), body, sensitiveBodyFields)
				}
				if truncated {
					logged += "...[truncated]"
				}
				event = event.Str("request_body", logged)
			}

			// Add response size
			if rw.size > 0 {
				event = event.Int("size", rw.size)
			}

			// Add custom fields
			if cfg.CustomFields != nil {
				for key, value := range cfg.CustomFields(r) {
					event = event.Interface(key, value)
				}
			}

			// Send log
			event.Msg("HTTP request")
		})
	}
}

// NewRequestID returns the request id this package puts on log lines and in
// the X-Request-ID header. Exported for framework adapters.
//
// Named NewRequestID rather than GenerateRequestID because MiddlewareConfig
// already has a GenerateRequestID field -- the caller's override -- and two
// spellings of the same idea one dot apart is how you end up calling the
// wrong one.
func NewRequestID() string {
	return uuid.New().String()
}
