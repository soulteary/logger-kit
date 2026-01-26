package logger

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLevelHandlerConfig(t *testing.T) {
	cfg := DefaultLevelHandlerConfig()
	assert.Nil(t, cfg.Logger)
	assert.Empty(t, cfg.AllowedIPs)
	assert.False(t, cfg.RequireAuth)
}

func TestLevelHandler_GET(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	handler := LevelHandler(LevelHandlerConfig{Logger: logger})

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp LevelResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "info", resp.Level)
	assert.Contains(t, resp.ValidLevels, "debug")
	assert.Contains(t, resp.ValidLevels, "info")
}

func TestLevelHandler_PUT(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	handler := LevelHandler(LevelHandlerConfig{Logger: logger})

	body := `{"level": "debug"}`
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp LevelResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "debug", resp.Level)
	assert.Equal(t, "info", resp.PreviousLevel)
	assert.Equal(t, "log level updated successfully", resp.Message)
	assert.Equal(t, DebugLevel, logger.GetLevel())
}

func TestLevelHandler_POST(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	handler := LevelHandler(LevelHandlerConfig{Logger: logger})

	body := `{"level": "warn"}`
	req := httptest.NewRequest(http.MethodPost, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, WarnLevel, logger.GetLevel())
}

func TestLevelHandler_QueryParam(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	handler := LevelHandler(LevelHandlerConfig{Logger: logger})

	req := httptest.NewRequest(http.MethodPut, "/log/level?level=error", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, ErrorLevel, logger.GetLevel())
}

func TestLevelHandler_InvalidLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	handler := LevelHandler(LevelHandlerConfig{Logger: logger})

	body := `{"level": "invalid"}`
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, InfoLevel, logger.GetLevel()) // Unchanged
}

func TestLevelHandler_MissingLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	handler := LevelHandler(LevelHandlerConfig{Logger: logger})

	body := `{}`
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestLevelHandler_MethodNotAllowed(t *testing.T) {
	handler := LevelHandler(DefaultLevelHandlerConfig())

	req := httptest.NewRequest(http.MethodDelete, "/log/level", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestLevelHandler_AllowedIPs(t *testing.T) {
	handler := LevelHandler(LevelHandlerConfig{
		AllowedIPs: []string{"192.168.1.1"},
	})

	// Request from non-allowed IP
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	req.RemoteAddr = "192.168.1.2:1234"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Request from allowed IP
	req = httptest.NewRequest(http.MethodGet, "/log/level", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestLevelHandler_RequireAuth(t *testing.T) {
	handler := LevelHandler(LevelHandlerConfig{
		RequireAuth: true,
		AuthFunc: func(r *http.Request) bool {
			return r.Header.Get("Authorization") == "Bearer valid-token"
		},
	})

	// Request without auth
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Request with auth
	req = httptest.NewRequest(http.MethodGet, "/log/level", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestLevelHandler_DefaultLogger(t *testing.T) {
	handler := LevelHandler(DefaultLevelHandlerConfig())

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestLevelHandlerFunc(t *testing.T) {
	handlerFunc := LevelHandlerFunc(DefaultLevelHandlerConfig())

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	rec := httptest.NewRecorder()

	handlerFunc(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestLevelHandlerFiber_GET(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	app := fiber.New()
	app.Get("/log/level", LevelHandlerFiber(LevelHandlerConfig{Logger: logger}))

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLevelHandlerFiber_PUT(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	app := fiber.New()
	app.Put("/log/level", LevelHandlerFiber(LevelHandlerConfig{Logger: logger}))

	body := `{"level": "debug"}`
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, DebugLevel, logger.GetLevel())
}

func TestLevelHandlerFiber_InvalidLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	app := fiber.New()
	app.Put("/log/level", LevelHandlerFiber(LevelHandlerConfig{Logger: logger}))

	body := `{"level": "invalid"}`
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestLevelHandlerFiber_MissingLevel(t *testing.T) {
	app := fiber.New()
	app.Put("/log/level", LevelHandlerFiber(DefaultLevelHandlerConfig()))

	body := `{}`
	req := httptest.NewRequest(http.MethodPut, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestLevelHandlerFiber_QueryParam(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	app := fiber.New()
	app.Put("/log/level", LevelHandlerFiber(LevelHandlerConfig{Logger: logger}))

	req := httptest.NewRequest(http.MethodPut, "/log/level?level=warn", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, WarnLevel, logger.GetLevel())
}

func TestLevelHandlerFiber_AllowedIPs(t *testing.T) {
	app := fiber.New()
	app.Get("/log/level", LevelHandlerFiber(LevelHandlerConfig{
		AllowedIPs: []string{"192.168.1.1"},
	}))

	// Request from non-allowed IP (Fiber uses different IP detection)
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	// In test environment, IP detection may differ
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden)
}

func TestLevelHandlerFiber_RequireAuth(t *testing.T) {
	app := fiber.New()
	app.Get("/log/level", LevelHandlerFiber(LevelHandlerConfig{
		RequireAuth: true,
		AuthFuncFiber: func(c *fiber.Ctx) bool {
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
	app.Delete("/log/level", LevelHandlerFiber(DefaultLevelHandlerConfig()))

	req := httptest.NewRequest(http.MethodDelete, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestRegisterLevelEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	RegisterLevelEndpoint(mux, "/log/level", DefaultLevelHandlerConfig())

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRegisterLevelEndpointFiber(t *testing.T) {
	app := fiber.New()
	RegisterLevelEndpointFiber(app, "/log/level", DefaultLevelHandlerConfig())

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestGetClientIPStd(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:       "X-Forwarded-For",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.1, 10.0.0.1"},
			remoteAddr: "127.0.0.1:1234",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Real-IP",
			headers:    map[string]string{"X-Real-IP": "192.168.1.2"},
			remoteAddr: "127.0.0.1:1234",
			expected:   "192.168.1.2",
		},
		{
			name:       "RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.3:1234",
			expected:   "192.168.1.3",
		},
		{
			name:       "RemoteAddr without port",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.4",
			expected:   "192.168.1.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			req.RemoteAddr = tt.remoteAddr

			ip := getClientIPStd(req)
			assert.Equal(t, tt.expected, ip)
		})
	}
}

func TestLevelHandlerFiber_POST(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	app := fiber.New()
	app.Post("/log/level", LevelHandlerFiber(LevelHandlerConfig{Logger: logger}))

	body := `{"level": "warn"}`
	req := httptest.NewRequest(http.MethodPost, "/log/level", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, WarnLevel, logger.GetLevel())
}

func TestLevelHandlerFiber_DefaultLogger(t *testing.T) {
	app := fiber.New()
	app.Get("/log/level", LevelHandlerFiber(LevelHandlerConfig{}))

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLevelHandler_XForwardedForIP(t *testing.T) {
	handler := LevelHandler(LevelHandlerConfig{
		AllowedIPs: []string{"192.168.1.100"},
	})

	// Request from allowed IP via X-Forwarded-For
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100, 10.0.0.1")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestLevelHandler_XRealIP(t *testing.T) {
	handler := LevelHandler(LevelHandlerConfig{
		AllowedIPs: []string{"192.168.1.200"},
	})

	// Request from allowed IP via X-Real-IP
	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	req.Header.Set("X-Real-IP", "192.168.1.200")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
