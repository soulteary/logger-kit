package logger

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContextWithLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  DebugLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	ctx := context.Background()
	ctx = ContextWithLogger(ctx, logger)

	retrieved := LoggerFromContext(ctx)
	assert.Equal(t, logger, retrieved)
}

func TestLoggerFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	logger := LoggerFromContext(ctx)
	assert.Equal(t, defaultLogger, logger)
}

func TestLoggerFromContext_Nil(t *testing.T) {
	//nolint:staticcheck // SA1012: intentionally testing nil context handling
	logger := LoggerFromContext(nil)
	assert.Equal(t, defaultLogger, logger)
}

func TestLoggerFromContextOK(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  DebugLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	ctx := context.Background()

	// Not found
	l, ok := LoggerFromContextOK(ctx)
	assert.Nil(t, l)
	assert.False(t, ok)

	// Found
	ctx = ContextWithLogger(ctx, logger)
	l, ok = LoggerFromContextOK(ctx)
	assert.Equal(t, logger, l)
	assert.True(t, ok)

	// Nil context
	//nolint:staticcheck // SA1012: intentionally testing nil context handling
	l, ok = LoggerFromContextOK(nil)
	assert.Nil(t, l)
	assert.False(t, ok)
}

func TestContextWithRequestID(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithRequestID(ctx, "req-123")

	id := RequestIDFromContext(ctx)
	assert.Equal(t, "req-123", id)
}

func TestRequestIDFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	id := RequestIDFromContext(ctx)
	assert.Empty(t, id)
}

func TestRequestIDFromContext_Nil(t *testing.T) {
	//nolint:staticcheck // SA1012: intentionally testing nil context handling
	id := RequestIDFromContext(nil)
	assert.Empty(t, id)
}

func TestContextWithTraceID(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithTraceID(ctx, "trace-456")

	id := TraceIDFromContext(ctx)
	assert.Equal(t, "trace-456", id)
}

func TestTraceIDFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	id := TraceIDFromContext(ctx)
	assert.Empty(t, id)
}

func TestTraceIDFromContext_Nil(t *testing.T) {
	//nolint:staticcheck // SA1012: intentionally testing nil context handling
	id := TraceIDFromContext(nil)
	assert.Empty(t, id)
}

func TestContextWithSpanID(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithSpanID(ctx, "span-789")

	id := SpanIDFromContext(ctx)
	assert.Equal(t, "span-789", id)
}

func TestSpanIDFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	id := SpanIDFromContext(ctx)
	assert.Empty(t, id)
}

func TestSpanIDFromContext_Nil(t *testing.T) {
	//nolint:staticcheck // SA1012: intentionally testing nil context handling
	id := SpanIDFromContext(nil)
	assert.Empty(t, id)
}

func TestContextWithUserID(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithUserID(ctx, "user-001")

	id := UserIDFromContext(ctx)
	assert.Equal(t, "user-001", id)
}

func TestUserIDFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	id := UserIDFromContext(ctx)
	assert.Empty(t, id)
}

func TestUserIDFromContext_Nil(t *testing.T) {
	//nolint:staticcheck // SA1012: intentionally testing nil context handling
	id := UserIDFromContext(nil)
	assert.Empty(t, id)
}

func TestContextWithIDs(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithIDs(ctx, "req-123", "trace-456", "span-789")

	assert.Equal(t, "req-123", RequestIDFromContext(ctx))
	assert.Equal(t, "trace-456", TraceIDFromContext(ctx))
	assert.Equal(t, "span-789", SpanIDFromContext(ctx))
}

func TestLogFromContext(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  DebugLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	ctx := context.Background()
	ctx = ContextWithLogger(ctx, logger)
	ctx = ContextWithRequestID(ctx, "req-123")
	ctx = ContextWithTraceID(ctx, "trace-456")
	ctx = ContextWithSpanID(ctx, "span-789")
	ctx = ContextWithUserID(ctx, "user-001")

	l := LogFromContext(ctx)
	assert.NotNil(t, l)

	l.Info().Msg("test message")

	output := buf.String()
	assert.Contains(t, output, "req-123")
	assert.Contains(t, output, "trace-456")
	assert.Contains(t, output, "span-789")
	assert.Contains(t, output, "user-001")
}

func TestCtx(t *testing.T) {
	ctx := context.Background()
	l := Ctx(ctx)
	assert.NotNil(t, l)
}

func TestSetLoggerInRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  DebugLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = SetLoggerInRequest(req, logger)

	retrieved := LoggerFromRequest(req)
	assert.Equal(t, logger, retrieved)
}

func TestLoggerFromRequest_Nil(t *testing.T) {
	logger := LoggerFromRequest(nil)
	assert.Equal(t, defaultLogger, logger)
}

func TestSetRequestIDInRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = SetRequestIDInRequest(req, "req-123")

	id := RequestIDFromRequest(req)
	assert.Equal(t, "req-123", id)
}

func TestRequestIDFromRequest_Nil(t *testing.T) {
	id := RequestIDFromRequest(nil)
	assert.Empty(t, id)
}

func TestSetTraceIDInRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = SetTraceIDInRequest(req, "trace-456")

	id := TraceIDFromRequest(req)
	assert.Equal(t, "trace-456", id)
}

func TestTraceIDFromRequest_Nil(t *testing.T) {
	id := TraceIDFromRequest(nil)
	assert.Empty(t, id)
}

func TestSetUserIDInRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = SetUserIDInRequest(req, "user-001")

	id := UserIDFromRequest(req)
	assert.Equal(t, "user-001", id)
}

func TestUserIDFromRequest_Nil(t *testing.T) {
	id := UserIDFromRequest(nil)
	assert.Empty(t, id)
}
