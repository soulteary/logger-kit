// Fiber adapter tests, moved here from the root package together with the
// handler and middleware they cover. External test package on purpose: they
// compile only against logger-kit's exported API, which is what an
// out-of-tree adapter has.
package fiberadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	logkit "github.com/soulteary/logger-kit/v3"
	"github.com/soulteary/logger-kit/v3/fiberadapter"
)

func TestFiberMiddleware_Basic(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{MiddlewareConfig: logkit.MiddlewareConfig{Logger: logger}}))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	output := buf.String()
	assert.Contains(t, output, "GET")
	assert.Contains(t, output, "/test")
}

func TestFiberMiddleware_SkipPaths(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger:    logger,
			SkipPaths: []string{"/health"},
		},
	}))
	app.Get("/health", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	app.Get("/api", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Skipped path
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	_, err := app.Test(req)
	require.NoError(t, err)
	assert.Empty(t, buf.String())

	// Logged path
	req = httptest.NewRequest(http.MethodGet, "/api", nil)
	_, err = app.Test(req)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String())
}

func TestFiberMiddleware_RequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger:           logger,
			IncludeRequestID: true,
		},
	}))
	app.Get("/test", func(c fiber.Ctx) error {
		id := fiberadapter.RequestID(c)
		assert.NotEmpty(t, id)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Header.Get("X-Request-ID"))
	assert.Contains(t, buf.String(), "request_id")
}

func TestFiberMiddleware_LogLevelsByStatus(t *testing.T) {
	tests := []struct {
		status        int
		expectedLevel string
	}{
		{200, "info"},
		{400, "warn"},
		{500, "error"},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			var buf bytes.Buffer
			logger := logkit.New(logkit.Config{
				Level:  logkit.TraceLevel,
				Output: &buf,
				Format: logkit.FormatJSON,
			})

			app := fiber.New()
			app.Use(fiberadapter.Middleware(fiberadapter.Config{MiddlewareConfig: logkit.MiddlewareConfig{Logger: logger}}))
			app.Get("/test", func(c fiber.Ctx) error {
				return c.SendStatus(tt.status)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			_, err := app.Test(req)
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &result)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedLevel, result["level"])
		})
	}
}

func TestLoggerFromFiberCtx(t *testing.T) {
	var buf bytes.Buffer
	expectedLogger := logkit.New(logkit.Config{
		Level:  logkit.DebugLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{MiddlewareConfig: logkit.MiddlewareConfig{Logger: expectedLogger}}))
	app.Get("/test", func(c fiber.Ctx) error {
		logger := fiberadapter.Logger(c)
		assert.Equal(t, expectedLogger, logger)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := app.Test(req)
	require.NoError(t, err)
}

func TestLoggerFromFiberCtx_NotFound(t *testing.T) {
	app := fiber.New()
	app.Get("/test", func(c fiber.Ctx) error {
		logger := fiberadapter.Logger(c)
		assert.Equal(t, logkit.Default(), logger)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := app.Test(req)
	require.NoError(t, err)
}

func TestRequestIDFromFiberCtx(t *testing.T) {
	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{MiddlewareConfig: logkit.MiddlewareConfig{IncludeRequestID: true}}))
	app.Get("/test", func(c fiber.Ctx) error {
		id := fiberadapter.RequestID(c)
		assert.NotEmpty(t, id)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := app.Test(req)
	require.NoError(t, err)
}

func TestRequestIDFromFiberCtx_NotFound(t *testing.T) {
	app := fiber.New()
	app.Get("/test", func(c fiber.Ctx) error {
		id := fiberadapter.RequestID(c)
		assert.Empty(t, id)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := app.Test(req)
	require.NoError(t, err)
}

func TestCtxFiber(t *testing.T) {
	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{MiddlewareConfig: logkit.MiddlewareConfig{IncludeRequestID: true}}))
	app.Get("/test", func(c fiber.Ctx) error {
		logger := fiberadapter.Ctx(c)
		assert.NotNil(t, logger)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := app.Test(req)
	require.NoError(t, err)
}

func TestFiberMiddleware_SkipFunc(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger: logger,
		},
		SkipFunc: func(c fiber.Ctx) bool {
			return c.Get("Skip-Logging") == "true"
		},
	}))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Skipped request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Skip-Logging", "true")
	_, err := app.Test(req)
	require.NoError(t, err)
	assert.Empty(t, buf.String())

	// Logged request
	buf.Reset()
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err = app.Test(req)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String())
}

func TestFiberMiddleware_IncludeQuery(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger:       logger,
			IncludeQuery: true,
		},
	}))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test?foo=bar&baz=qux", nil)
	_, err := app.Test(req)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "foo=bar")
	assert.Contains(t, output, "baz=qux")
}

func TestFiberMiddleware_IncludeHeaders(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger:         logger,
			IncludeHeaders: true,
		},
	}))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Custom-Header", "custom-value")
	req.Header.Set("Authorization", "Bearer secret-token")
	_, err := app.Test(req)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "X-Custom-Header")
	assert.Contains(t, output, "custom-value")
	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "secret-token")
}

func TestFiberMiddleware_IncludeBody(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger:      logger,
			IncludeBody: true,
			MaxBodySize: 100,
		},
	}))
	app.Post("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Small body
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"key":"value"}`))
	req.Header.Set("Content-Type", "application/json")
	_, err := app.Test(req)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "request_body")
	assert.Contains(t, output, "key")
}

func TestFiberMiddleware_IncludeBody_Truncated(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger:      logger,
			IncludeBody: true,
			MaxBodySize: 10, // Very small limit
		},
	}))
	app.Post("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Large body that will be truncated
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"key":"this is a very long value that exceeds the max body size"}`))
	req.Header.Set("Content-Type", "application/json")
	_, err := app.Test(req)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "[truncated]")
}

func TestFiberMiddleware_CustomFields(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger: logger,
		},
		CustomFields: func(c fiber.Ctx) map[string]interface{} {
			return map[string]interface{}{
				"custom_field": "custom_value",
			}
		},
	}))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := app.Test(req)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "custom_field")
	assert.Contains(t, output, "custom_value")
}

func TestFiberMiddleware_WithError(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{MiddlewareConfig: logkit.MiddlewareConfig{Logger: logger}}))
	app.Get("/test", func(c fiber.Ctx) error {
		return fiber.NewError(fiber.StatusInternalServerError, "test error")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := app.Test(req)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "error")
}

func TestFiberMiddleware_ExistingRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger:           logger,
			IncludeRequestID: true,
		},
	}))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Request with existing request ID
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", "existing-request-id")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, "existing-request-id", resp.Header.Get("X-Request-ID"))
	assert.Contains(t, buf.String(), "existing-request-id")
}

func TestFiberMiddleware_CustomRequestIDGenerator(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{
			Logger:           logger,
			IncludeRequestID: true,
			GenerateRequestID: func() string {
				return "custom-generated-id"
			},
		},
	}))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, "custom-generated-id", resp.Header.Get("X-Request-ID"))
}

func TestLevelHandlerFiber_GET(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Get("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{LevelHandlerConfig: logkit.LevelHandlerConfig{Logger: logger}}))

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLevelHandlerFiber_PUT(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Put("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{LevelHandlerConfig: logkit.LevelHandlerConfig{Logger: logger}}))

	body := `{"level": "debug"}`
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, logkit.DebugLevel, logger.GetLevel())
}

func TestLevelHandlerFiber_InvalidLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Put("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{LevelHandlerConfig: logkit.LevelHandlerConfig{Logger: logger}}))

	body := `{"level": "invalid"}`
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestLevelHandlerFiber_MissingLevel(t *testing.T) {
	app := fiber.New()
	app.Put("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{LevelHandlerConfig: logkit.DefaultLevelHandlerConfig()}))

	body := `{}`
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestLevelHandlerFiber_QueryParam(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Put("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{LevelHandlerConfig: logkit.LevelHandlerConfig{Logger: logger}}))

	req := httptest.NewRequest(http.MethodPut, "/log/level?level=warn", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, logkit.WarnLevel, logger.GetLevel())
}

func TestLevelHandlerFiber_AllowedIPs(t *testing.T) {
	app := fiber.New()
	app.Get("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{
		LevelHandlerConfig: logkit.LevelHandlerConfig{
			AllowedIPs: []string{"192.168.1.1"},
		},
	}))

	// app.Test dials from fiberTestPeer, which is not on the list.
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestLevelHandlerFiber_RequireAuth(t *testing.T) {
	app := fiber.New()
	app.Get("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{
		LevelHandlerConfig: logkit.LevelHandlerConfig{
			RequireAuth: true,
		},
		AuthFunc: func(c fiber.Ctx) bool {
			return c.Get("Authorization") == "Bearer valid-token"
		},
	}))

	// Request without auth
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Request with auth
	req = httptest.NewRequest(http.MethodGet, "/log/level", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err = app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLevelHandlerFiber_MethodNotAllowed(t *testing.T) {
	app := fiber.New()
	app.Delete("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{LevelHandlerConfig: logkit.DefaultLevelHandlerConfig()}))

	req := httptest.NewRequest(http.MethodDelete, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestRegisterLevelEndpointFiber(t *testing.T) {
	app := fiber.New()
	fiberadapter.RegisterLevelEndpoint(app, "/log/level", fiberadapter.LevelHandlerConfig{LevelHandlerConfig: logkit.DefaultLevelHandlerConfig()})

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLevelHandlerFiber_POST(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Post("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{LevelHandlerConfig: logkit.LevelHandlerConfig{Logger: logger}}))

	body := `{"level": "warn"}`
	req := httptest.NewRequest(http.MethodPost, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, logkit.WarnLevel, logger.GetLevel())
}

func TestLevelHandlerFiber_DefaultLogger(t *testing.T) {
	app := fiber.New()
	app.Get("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{LevelHandlerConfig: logkit.LevelHandlerConfig{}}))

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLevelHandlerFiber_RequireAuth_NoAuthFuncFiber(t *testing.T) {
	app := fiber.New()
	app.Get("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{
		LevelHandlerConfig: logkit.LevelHandlerConfig{
			RequireAuth: true,
		},
		AuthFunc: nil,
	}))

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestLevelHandlerFiber_BodyTooLarge(t *testing.T) {
	var buf bytes.Buffer
	logger := logkit.New(logkit.Config{
		Level:  logkit.InfoLevel,
		Output: &buf,
		Format: logkit.FormatJSON,
	})

	app := fiber.New()
	app.Put("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{
		LevelHandlerConfig: logkit.LevelHandlerConfig{
			Logger:       logger,
			MaxBodyBytes: 5,
		},
	}))

	body := `{"level": "debug"}` // > 5 bytes
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}
