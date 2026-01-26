package logger

import (
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
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

	// SkipFuncFiber is a function to determine if logging should be skipped (Fiber).
	SkipFuncFiber func(c *fiber.Ctx) bool

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

	// IncludeBody includes request body in logs.
	// Warning: This may log sensitive data.
	// Default: false
	IncludeBody bool

	// MaxBodySize is the maximum body size to log (in bytes).
	// Bodies larger than this are truncated.
	// Default: 1024
	MaxBodySize int

	// CustomFields adds custom fields to each log entry.
	CustomFields func(r *http.Request) map[string]interface{}

	// CustomFieldsFiber adds custom fields to each log entry (Fiber).
	CustomFieldsFiber func(c *fiber.Ctx) map[string]interface{}
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
	}
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

// Middleware creates a standard net/http logging middleware.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = defaultLogger
	}
	if cfg.RequestIDHeader == "" {
		cfg.RequestIDHeader = "X-Request-ID"
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = 1024
	}
	// Apply default log levels if not set (zero value is DebugLevel)
	// We check if all three are at their zero value to avoid overwriting intentional DebugLevel
	defaults := DefaultMiddlewareConfig()
	if cfg.LogLevel == DebugLevel && cfg.WarnLevel == DebugLevel && cfg.ErrorLevel == DebugLevel {
		cfg.LogLevel = defaults.LogLevel
		cfg.WarnLevel = defaults.WarnLevel
		cfg.ErrorLevel = defaults.ErrorLevel
	}

	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}

	sensitiveHeaderMap := make(map[string]bool)
	if len(cfg.SensitiveHeaders) == 0 {
		cfg.SensitiveHeaders = []string{"Authorization", "X-API-Key", "X-Signature", "Cookie", "Set-Cookie"}
	}
	for _, h := range cfg.SensitiveHeaders {
		sensitiveHeaderMap[strings.ToLower(h)] = true
	}

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
					requestID = generateUUID()
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
				Str("ip", getClientIPStd(r)).
				Str("user_agent", r.UserAgent())

			// Add request ID
			if cfg.IncludeRequestID && requestID != "" {
				event = event.Str("request_id", requestID)
			}

			// Add latency
			if cfg.IncludeLatency {
				event = event.Dur("latency", latency)
			}

			// Add query parameters
			if cfg.IncludeQuery && r.URL.RawQuery != "" {
				event = event.Str("query", r.URL.RawQuery)
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

// FiberMiddleware creates a Fiber logging middleware.
func FiberMiddleware(cfg MiddlewareConfig) fiber.Handler {
	if cfg.Logger == nil {
		cfg.Logger = defaultLogger
	}
	if cfg.RequestIDHeader == "" {
		cfg.RequestIDHeader = "X-Request-ID"
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = 1024
	}
	// Apply default log levels if not set (zero value is DebugLevel)
	defaults := DefaultMiddlewareConfig()
	if cfg.LogLevel == DebugLevel && cfg.WarnLevel == DebugLevel && cfg.ErrorLevel == DebugLevel {
		cfg.LogLevel = defaults.LogLevel
		cfg.WarnLevel = defaults.WarnLevel
		cfg.ErrorLevel = defaults.ErrorLevel
	}

	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}

	sensitiveHeaderMap := make(map[string]bool)
	if len(cfg.SensitiveHeaders) == 0 {
		cfg.SensitiveHeaders = []string{"Authorization", "X-API-Key", "X-Signature", "Cookie", "Set-Cookie"}
	}
	for _, h := range cfg.SensitiveHeaders {
		sensitiveHeaderMap[strings.ToLower(h)] = true
	}

	return func(c *fiber.Ctx) error {
		// Skip if path is in skip list
		if skipPathMap[c.Path()] {
			return c.Next()
		}

		// Skip if skip function returns true
		if cfg.SkipFuncFiber != nil && cfg.SkipFuncFiber(c) {
			return c.Next()
		}

		start := time.Now()

		// Handle request ID
		requestID := c.Get(cfg.RequestIDHeader)
		if requestID == "" && cfg.IncludeRequestID {
			if cfg.GenerateRequestID != nil {
				requestID = cfg.GenerateRequestID()
			} else {
				requestID = generateUUID()
			}
			c.Request().Header.Set(cfg.RequestIDHeader, requestID)
		}

		// Set request ID in response header
		if cfg.IncludeRequestID && requestID != "" {
			c.Set(cfg.RequestIDHeader, requestID)
		}

		// Store request ID in locals
		if requestID != "" {
			c.Locals("request_id", requestID)
		}

		// Store logger in locals
		c.Locals("logger", cfg.Logger)

		// Process request
		err := c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get status code
		status := c.Response().StatusCode()

		// Determine log level based on status code
		var logLevel Level
		switch {
		case status >= 500:
			logLevel = cfg.ErrorLevel
		case status >= 400:
			logLevel = cfg.WarnLevel
		default:
			logLevel = cfg.LogLevel
		}

		// Build log event
		zl := cfg.Logger.Zerolog()
		event := zl.WithLevel(logLevel.ToZerolog())

		// Add standard fields
		event = event.
			Str("method", c.Method()).
			Str("path", c.Path()).
			Int("status", status).
			Str("ip", c.IP()).
			Str("user_agent", c.Get("User-Agent"))

		// Add request ID
		if cfg.IncludeRequestID && requestID != "" {
			event = event.Str("request_id", requestID)
		}

		// Add latency
		if cfg.IncludeLatency {
			event = event.Dur("latency", latency)
		}

		// Add query parameters
		if cfg.IncludeQuery {
			query := c.Request().URI().QueryString()
			if len(query) > 0 {
				event = event.Str("query", string(query))
			}
		}

		// Add headers
		if cfg.IncludeHeaders {
			headers := make(map[string]string)
			c.Request().Header.VisitAll(func(key, value []byte) {
				headerName := string(key)
				if sensitiveHeaderMap[strings.ToLower(headerName)] {
					headers[headerName] = "[REDACTED]"
				} else {
					headers[headerName] = string(value)
				}
			})
			event = event.Interface("headers", headers)
		}

		// Add request body if enabled
		if cfg.IncludeBody {
			body := c.Body()
			if len(body) > cfg.MaxBodySize {
				event = event.Str("request_body", string(body[:cfg.MaxBodySize])+"...[truncated]")
			} else if len(body) > 0 {
				event = event.Str("request_body", string(body))
			}
		}

		// Add custom fields
		if cfg.CustomFieldsFiber != nil {
			for key, value := range cfg.CustomFieldsFiber(c) {
				event = event.Interface(key, value)
			}
		}

		// Add error if present
		if err != nil {
			event = event.Err(err)
		}

		// Send log
		event.Msg("HTTP request")

		return err
	}
}

// LoggerFromFiberCtx extracts the logger from Fiber context.
func LoggerFromFiberCtx(c *fiber.Ctx) *Logger {
	if l, ok := c.Locals("logger").(*Logger); ok {
		return l
	}
	return defaultLogger
}

// RequestIDFromFiberCtx extracts the request ID from Fiber context.
func RequestIDFromFiberCtx(c *fiber.Ctx) string {
	if id, ok := c.Locals("request_id").(string); ok {
		return id
	}
	return ""
}

// CtxFiber returns a zerolog.Logger enriched with Fiber context values.
func CtxFiber(c *fiber.Ctx) *zerolog.Logger {
	l := LoggerFromFiberCtx(c)
	logger := l.Zerolog()

	if requestID := RequestIDFromFiberCtx(c); requestID != "" {
		logger = logger.With().Str("request_id", requestID).Logger()
	}

	return &logger
}

// generateUUID generates a simple UUID v4.
func generateUUID() string {
	// Simple UUID generation without external dependency
	// Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
	const hexChars = "0123456789abcdef"
	uuid := make([]byte, 36)

	for i := range uuid {
		switch i {
		case 8, 13, 18, 23:
			uuid[i] = '-'
		case 14:
			uuid[i] = '4'
		case 19:
			uuid[i] = hexChars[(randByte()&0x3)|0x8]
		default:
			uuid[i] = hexChars[randByte()&0xf]
		}
	}

	return string(uuid)
}

// randByte returns a pseudo-random byte.
// Uses a combination of time, counter, and memory address for better uniqueness.
var randCounter uint64
var randSeed = uint64(time.Now().UnixNano())

func randByte() byte {
	randCounter++
	// Mix multiple sources of entropy
	now := uint64(time.Now().UnixNano())
	mixed := now ^ randSeed ^ (randCounter * 6364136223846793005)
	randSeed = mixed
	return byte(mixed >> ((randCounter % 8) * 8))
}
