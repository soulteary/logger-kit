// Tests for the Fiber side of the shared trusted-proxy rule.
//
// Source is the whole of what this adapter contributes to client-IP
// resolution: the rule itself lives in the root package and is tested there.
// But Source.Header is what feeds it, and if it read the wrong thing every
// AllowedIPs decision made behind a proxy would be wrong on Fiber and right on
// net/http -- which is exactly the divergence the fiberadapter split exists to
// prevent. So it gets asserted here rather than left to the root-package tests.
package fiberadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	logkit "github.com/soulteary/logger-kit/v2"
	"github.com/soulteary/logger-kit/v2/fiberadapter"
)

// fiberTestPeer is the RemoteAddr fiber's app.Test gives every request.
const fiberTestPeer = "0.0.0.0"

func TestSource_ReadsRemoteAddrAndHeaders(t *testing.T) {
	app := fiber.New()

	var remote, xff, xri, missing string
	app.Get("/probe", func(c fiber.Ctx) error {
		src := fiberadapter.Source{C: c}
		remote = src.RemoteAddr()
		xff = src.Header("X-Forwarded-For")
		xri = src.Header("X-Real-IP")
		missing = src.Header("X-Absent")
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	_, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, fiberTestPeer+":0", remote)
	assert.Equal(t, "203.0.113.9, 198.51.100.7", xff)
	assert.Equal(t, "203.0.113.10", xri)
	assert.Equal(t, "", missing, "an absent header must read as empty, not panic")
}

// TestSource_FeedsTheSharedRule drives logger.ClientIP with a real fiber.Ctx,
// so the Fiber adapter and net/http are pinned to the same answers.
func TestSource_FeedsTheSharedRule(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		trusted []string
		want    string
	}{
		{
			name:    "no trusted proxies: forwarded headers are ignored",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: nil,
			want:    fiberTestPeer,
		},
		{
			name:    "peer not in a non-empty trusted list is not believed",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"198.51.100.1"},
			want:    fiberTestPeer,
		},
		{
			name:    "trusted peer: first X-Forwarded-For entry wins",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9, 198.51.100.7"},
			trusted: []string{fiberTestPeer},
			want:    "203.0.113.9",
		},
		{
			name:    "trusted peer: falls back to X-Real-IP",
			headers: map[string]string{"X-Real-IP": "203.0.113.10"},
			trusted: []string{fiberTestPeer},
			want:    "203.0.113.10",
		},
		{
			name:    "trusted peer with no proxy headers falls back to the peer",
			trusted: []string{fiberTestPeer},
			want:    fiberTestPeer,
		},
		{
			name:    "trusted peer matched by CIDR",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"0.0.0.0/8"},
			want:    "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			var got string
			app.Get("/probe", func(c fiber.Ctx) error {
				got = logkit.ClientIP(fiberadapter.Source{C: c}, tt.trusted)
				return c.SendStatus(fiber.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/probe", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			_, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFiberMiddleware_LogsForwardedIPOnlyFromATrustedProxy(t *testing.T) {
	logIP := func(t *testing.T, trusted []string) string {
		t.Helper()
		var buf bytes.Buffer
		log := logkit.New(logkit.Config{Level: logkit.InfoLevel, Output: &buf, Format: logkit.FormatJSON})

		app := fiber.New()
		app.Use(fiberadapter.Middleware(fiberadapter.Config{
			MiddlewareConfig: logkit.MiddlewareConfig{Logger: log, TrustedProxies: trusted},
		}))
		app.Get("/test", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.9")
		_, err := app.Test(req)
		require.NoError(t, err)

		var entry map[string]interface{}
		require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
		ip, _ := entry["ip"].(string)
		return ip
	}

	assert.Equal(t, fiberTestPeer, logIP(t, nil),
		"an untrusted peer's X-Forwarded-For must not reach the log")
	assert.Equal(t, "203.0.113.9", logIP(t, []string{fiberTestPeer}))
}

func TestLevelHandlerFiber_AllowedIPs_SpoofAttempt(t *testing.T) {
	// The peer is 0.0.0.0 and nothing is trusted, so a forwarded header
	// claiming an allowed IP must not open the endpoint.
	app := fiber.New()
	app.Get("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{
		LevelHandlerConfig: logkit.LevelHandlerConfig{
			AllowedIPs: []string{"192.0.2.1"},
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	req.Header.Set("X-Forwarded-For", "192.0.2.1")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestLevelHandlerFiber_AllowedIPs_TrustedProxy(t *testing.T) {
	app := fiber.New()
	app.Get("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{
		LevelHandlerConfig: logkit.LevelHandlerConfig{
			AllowedIPs:     []string{"192.0.2.1"},
			TrustedProxies: []string{fiberTestPeer},
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/log/level", nil)
	req.Header.Set("X-Forwarded-For", "192.0.2.1")
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLevelHandlerFiber_AllowedIPs_DirectPeerListed(t *testing.T) {
	app := fiber.New()
	app.Get("/log/level", fiberadapter.LevelHandler(fiberadapter.LevelHandlerConfig{
		LevelHandlerConfig: logkit.LevelHandlerConfig{
			AllowedIPs: []string{fiberTestPeer},
		},
	}))

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/log/level", nil))
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestFiberMiddleware_NoConfig(t *testing.T) {
	// Middleware() with no argument must still produce a working middleware
	// on the package defaults.
	app := fiber.New()
	app.Use(fiberadapter.Middleware())
	app.Get("/test", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("X-Request-ID"),
		"IncludeRequestID defaults to true, so the response must carry one")
}

func TestFiberMiddleware_IncludeLatencyDisabled(t *testing.T) {
	var buf bytes.Buffer
	log := logkit.New(logkit.Config{Level: logkit.InfoLevel, Output: &buf, Format: logkit.FormatJSON})

	app := fiber.New()
	app.Use(fiberadapter.Middleware(fiberadapter.Config{
		MiddlewareConfig: logkit.MiddlewareConfig{Logger: log, IncludeLatency: false},
	}))
	app.Get("/test", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	_, err := app.Test(httptest.NewRequest(http.MethodGet, "/test", nil))
	require.NoError(t, err)

	var entry map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.NotContains(t, entry, "latency")
	assert.Equal(t, "/test", entry["path"], "the rest of the entry is unaffected")
}
