package logger

import (
	"context"
	"net/http"

	"github.com/rs/zerolog"
)

// contextKey is used to store values in context.
type contextKey string

const (
	// loggerContextKey is the context key for storing a logger.
	loggerContextKey contextKey = "logger-kit-logger"

	// requestIDContextKey is the context key for storing request ID.
	requestIDContextKey contextKey = "logger-kit-request-id"

	// traceIDContextKey is the context key for storing trace ID.
	traceIDContextKey contextKey = "logger-kit-trace-id"

	// spanIDContextKey is the context key for storing span ID.
	spanIDContextKey contextKey = "logger-kit-span-id"

	// userIDContextKey is the context key for storing user ID.
	userIDContextKey contextKey = "logger-kit-user-id"
)

// ContextWithLogger returns a new context with the logger.
func ContextWithLogger(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey, l)
}

// LoggerFromContext extracts the logger from the context.
// Returns the default logger if not found.
func LoggerFromContext(ctx context.Context) *Logger {
	if ctx == nil {
		return defaultLogger
	}
	if l, ok := ctx.Value(loggerContextKey).(*Logger); ok {
		return l
	}
	return defaultLogger
}

// LoggerFromContextOK extracts the logger from the context.
// Returns (nil, false) if not found.
func LoggerFromContextOK(ctx context.Context) (*Logger, bool) {
	if ctx == nil {
		return nil, false
	}
	l, ok := ctx.Value(loggerContextKey).(*Logger)
	return l, ok
}

// ContextWithRequestID returns a new context with the request ID.
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey, requestID)
}

// RequestIDFromContext extracts the request ID from the context.
// Returns empty string if not found.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(requestIDContextKey).(string); ok {
		return id
	}
	return ""
}

// ContextWithTraceID returns a new context with the trace ID.
func ContextWithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDContextKey, traceID)
}

// TraceIDFromContext extracts the trace ID from the context.
// Returns empty string if not found.
func TraceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(traceIDContextKey).(string); ok {
		return id
	}
	return ""
}

// ContextWithSpanID returns a new context with the span ID.
func ContextWithSpanID(ctx context.Context, spanID string) context.Context {
	return context.WithValue(ctx, spanIDContextKey, spanID)
}

// SpanIDFromContext extracts the span ID from the context.
// Returns empty string if not found.
func SpanIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(spanIDContextKey).(string); ok {
		return id
	}
	return ""
}

// ContextWithUserID returns a new context with the user ID.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDContextKey, userID)
}

// UserIDFromContext extracts the user ID from the context.
// Returns empty string if not found.
func UserIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(userIDContextKey).(string); ok {
		return id
	}
	return ""
}

// ContextWithIDs returns a new context with request ID, trace ID, and span ID.
func ContextWithIDs(ctx context.Context, requestID, traceID, spanID string) context.Context {
	ctx = ContextWithRequestID(ctx, requestID)
	ctx = ContextWithTraceID(ctx, traceID)
	ctx = ContextWithSpanID(ctx, spanID)
	return ctx
}

// LogFromContext returns a zerolog.Logger enriched with context values.
// It includes request_id, trace_id, span_id, and user_id if present.
func LogFromContext(ctx context.Context) *zerolog.Logger {
	l := LoggerFromContext(ctx)
	logger := l.Zerolog()

	// Add context values
	if requestID := RequestIDFromContext(ctx); requestID != "" {
		logger = logger.With().Str("request_id", requestID).Logger()
	}
	if traceID := TraceIDFromContext(ctx); traceID != "" {
		logger = logger.With().Str("trace_id", traceID).Logger()
	}
	if spanID := SpanIDFromContext(ctx); spanID != "" {
		logger = logger.With().Str("span_id", spanID).Logger()
	}
	if userID := UserIDFromContext(ctx); userID != "" {
		logger = logger.With().Str("user_id", userID).Logger()
	}

	return &logger
}

// Ctx is a shorthand for LogFromContext.
func Ctx(ctx context.Context) *zerolog.Logger {
	return LogFromContext(ctx)
}

// SetLoggerInRequest sets the logger in the request context.
func SetLoggerInRequest(r *http.Request, l *Logger) *http.Request {
	return r.WithContext(ContextWithLogger(r.Context(), l))
}

// LoggerFromRequest extracts the logger from the request context.
// Returns the default logger if not found.
func LoggerFromRequest(r *http.Request) *Logger {
	if r == nil {
		return defaultLogger
	}
	return LoggerFromContext(r.Context())
}

// SetRequestIDInRequest sets the request ID in the request context.
func SetRequestIDInRequest(r *http.Request, requestID string) *http.Request {
	return r.WithContext(ContextWithRequestID(r.Context(), requestID))
}

// RequestIDFromRequest extracts the request ID from the request context.
func RequestIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return RequestIDFromContext(r.Context())
}

// SetTraceIDInRequest sets the trace ID in the request context.
func SetTraceIDInRequest(r *http.Request, traceID string) *http.Request {
	return r.WithContext(ContextWithTraceID(r.Context(), traceID))
}

// TraceIDFromRequest extracts the trace ID from the request context.
func TraceIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return TraceIDFromContext(r.Context())
}

// SetUserIDInRequest sets the user ID in the request context.
func SetUserIDInRequest(r *http.Request, userID string) *http.Request {
	return r.WithContext(ContextWithUserID(r.Context(), userID))
}

// UserIDFromRequest extracts the user ID from the request context.
func UserIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return UserIDFromContext(r.Context())
}
