// Contract tests for the API an out-of-tree framework adapter builds on.
//
// External test package on purpose: these compile only against the exported
// surface, which is exactly what an Echo, Gin or chi adapter has. The Middleware
// and LevelHandler tests already run these code paths transitively, but an
// adapter calls them directly -- so the contract they depend on gets its own
// assertions here, not just statement coverage borrowed from a handler test.
package logger_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	logkit "github.com/soulteary/logger-kit/v2"
)

// fakeSource is the minimal ClientIPSource an adapter would write.
type fakeSource struct {
	remote  string
	headers map[string]string
}

func (f fakeSource) RemoteAddr() string { return f.remote }
func (f fakeSource) Header(name string) string {
	return f.headers[name]
}

func TestClientIP_TrustedProxyRule(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		headers map[string]string
		trusted []string
		want    string
	}{
		{
			name:    "no trusted proxies ignores X-Forwarded-For",
			remote:  "10.0.0.5:4321",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: nil,
			want:    "10.0.0.5",
		},
		{
			name:    "no trusted proxies ignores X-Real-IP",
			remote:  "10.0.0.5:4321",
			headers: map[string]string{"X-Real-IP": "203.0.113.9"},
			trusted: nil,
			want:    "10.0.0.5",
		},
		{
			name:    "peer not in a non-empty trusted list is not believed",
			remote:  "10.0.0.5:4321",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"192.0.2.1"},
			want:    "10.0.0.5",
		},
		{
			name:    "trusted peer: first X-Forwarded-For entry wins",
			remote:  "192.0.2.1:4321",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9, 198.51.100.7"},
			trusted: []string{"192.0.2.1"},
			want:    "203.0.113.9",
		},
		{
			name:    "trusted peer: falls back to X-Real-IP",
			remote:  "192.0.2.1:4321",
			headers: map[string]string{"X-Real-IP": " 203.0.113.9 "},
			trusted: []string{"192.0.2.1"},
			want:    "203.0.113.9",
		},
		{
			name:    "trusted peer with no proxy headers falls back to the peer",
			remote:  "192.0.2.1:4321",
			trusted: []string{"192.0.2.1"},
			want:    "192.0.2.1",
		},
		{
			name:    "trusted peer matched by CIDR",
			remote:  "192.0.2.77:4321",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"192.0.2.0/24"},
			want:    "203.0.113.9",
		},
		{
			name:    "malformed CIDR entry is skipped, later entry still matches",
			remote:  "192.0.2.1:4321",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"10.0.0.0/99", "192.0.2.1"},
			want:    "203.0.113.9",
		},
		{
			name:    "malformed CIDR entry alone trusts nobody",
			remote:  "192.0.2.1:4321",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"10.0.0.0/99"},
			want:    "192.0.2.1",
		},
		{
			name:    "unparseable peer address is never trusted",
			remote:  "not-an-ip:4321",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"192.0.2.1"},
			want:    "not-an-ip",
		},
		{
			name:    "empty RemoteAddr yields empty IP",
			remote:  "",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"192.0.2.1"},
			want:    "",
		},
		{
			name:    "IPv6 peer is unbracketed",
			remote:  "[2001:db8::1]:4321",
			trusted: nil,
			want:    "2001:db8::1",
		},
		{
			name:    "IPv6 peer matched by CIDR trusts the forwarded header",
			remote:  "[2001:db8::1]:4321",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"2001:db8::/32"},
			want:    "203.0.113.9",
		},
		{
			name:    "address without a port is used as-is",
			remote:  "192.0.2.1",
			trusted: nil,
			want:    "192.0.2.1",
		},
		{
			name:    "trusted list entries are trimmed",
			remote:  "192.0.2.1:4321",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.9"},
			trusted: []string{"  192.0.2.1  "},
			want:    "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := logkit.ClientIP(fakeSource{remote: tt.remote, headers: tt.headers}, tt.trusted)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRequestSource_ReadsRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	src := logkit.RequestSource(req)
	assert.Equal(t, "192.0.2.1:4321", src.RemoteAddr())
	assert.Equal(t, "203.0.113.9", src.Header("X-Forwarded-For"))
	// Header lookup is canonicalised, the way net/http does it.
	assert.Equal(t, "203.0.113.9", src.Header("x-forwarded-for"))
	assert.Equal(t, "", src.Header("X-Real-IP"))

	// Same rule, driven through the std adapter.
	assert.Equal(t, "192.0.2.1", logkit.ClientIP(src, nil))
	assert.Equal(t, "203.0.113.9", logkit.ClientIP(src, []string{"192.0.2.1"}))
}

func TestLevelHandlerConfig_Authorize(t *testing.T) {
	peer := fakeSource{remote: "192.0.2.1:4321"}

	t.Run("open config admits everyone", func(t *testing.T) {
		cfg := logkit.LevelHandlerConfig{}
		assert.Nil(t, cfg.Authorize(peer, false))
	})

	t.Run("RequireAuth rejects an unauthenticated caller", func(t *testing.T) {
		cfg := logkit.LevelHandlerConfig{RequireAuth: true}
		denied := cfg.Authorize(peer, false)
		require.NotNil(t, denied)
		assert.Equal(t, http.StatusUnauthorized, denied.StatusCode)
		assert.Equal(t, "Unauthorized", denied.Error)
		assert.Nil(t, denied.Body)
	})

	t.Run("RequireAuth admits an authenticated caller", func(t *testing.T) {
		cfg := logkit.LevelHandlerConfig{RequireAuth: true}
		assert.Nil(t, cfg.Authorize(peer, true))
	})

	t.Run("authenticated flag is ignored when RequireAuth is off", func(t *testing.T) {
		cfg := logkit.LevelHandlerConfig{}
		assert.Nil(t, cfg.Authorize(peer, false))
	})

	t.Run("AllowedIPs admits a listed peer", func(t *testing.T) {
		cfg := logkit.LevelHandlerConfig{AllowedIPs: []string{"192.0.2.1"}}
		assert.Nil(t, cfg.Authorize(peer, true))
	})

	t.Run("AllowedIPs rejects an unlisted peer", func(t *testing.T) {
		cfg := logkit.LevelHandlerConfig{AllowedIPs: []string{"198.51.100.1"}}
		denied := cfg.Authorize(peer, true)
		require.NotNil(t, denied)
		assert.Equal(t, http.StatusForbidden, denied.StatusCode)
		assert.Equal(t, "Forbidden", denied.Error)
	})

	t.Run("AllowedIPs is not spoofable without TrustedProxies", func(t *testing.T) {
		spoofer := fakeSource{
			remote:  "198.51.100.1:4321",
			headers: map[string]string{"X-Forwarded-For": "192.0.2.1"},
		}
		cfg := logkit.LevelHandlerConfig{AllowedIPs: []string{"192.0.2.1"}}
		denied := cfg.Authorize(spoofer, true)
		require.NotNil(t, denied, "forwarded header must not grant access")
		assert.Equal(t, http.StatusForbidden, denied.StatusCode)
	})

	t.Run("AllowedIPs honours a forwarded IP from a trusted proxy", func(t *testing.T) {
		proxied := fakeSource{
			remote:  "198.51.100.1:4321",
			headers: map[string]string{"X-Forwarded-For": "192.0.2.1"},
		}
		cfg := logkit.LevelHandlerConfig{
			AllowedIPs:     []string{"192.0.2.1"},
			TrustedProxies: []string{"198.51.100.1"},
		}
		assert.Nil(t, cfg.Authorize(proxied, true))
	})

	t.Run("auth is checked before the IP gate", func(t *testing.T) {
		cfg := logkit.LevelHandlerConfig{
			RequireAuth: true,
			AllowedIPs:  []string{"198.51.100.1"},
		}
		denied := cfg.Authorize(peer, false)
		require.NotNil(t, denied)
		assert.Equal(t, http.StatusUnauthorized, denied.StatusCode)
	})
}

func TestLevelHandlerConfig_CurrentLevel(t *testing.T) {
	var buf bytes.Buffer
	log := logkit.New(logkit.Config{Level: logkit.WarnLevel, Output: &buf, Format: logkit.FormatJSON})

	outcome := logkit.LevelHandlerConfig{Logger: log}.CurrentLevel()
	assert.Equal(t, http.StatusOK, outcome.StatusCode)
	assert.Empty(t, outcome.Error)
	require.NotNil(t, outcome.Body)
	assert.Equal(t, "warn", outcome.Body.Level)
	assert.Equal(t, logkit.ValidLevelStrings(), outcome.Body.ValidLevels)
	assert.Empty(t, outcome.Body.PreviousLevel)
	assert.Empty(t, outcome.Body.Message)
}

func TestLevelHandlerConfig_ApplyLevel(t *testing.T) {
	newCfg := func() (logkit.LevelHandlerConfig, *logkit.Logger) {
		var buf bytes.Buffer
		log := logkit.New(logkit.Config{Level: logkit.InfoLevel, Output: &buf, Format: logkit.FormatJSON})
		return logkit.LevelHandlerConfig{Logger: log}, log
	}

	t.Run("sets the level and reports the previous one", func(t *testing.T) {
		cfg, log := newCfg()
		outcome := cfg.ApplyLevel("debug")
		assert.Equal(t, http.StatusOK, outcome.StatusCode)
		require.NotNil(t, outcome.Body)
		assert.Equal(t, "debug", outcome.Body.Level)
		assert.Equal(t, "info", outcome.Body.PreviousLevel)
		assert.Equal(t, "log level updated successfully", outcome.Body.Message)
		assert.Equal(t, logkit.DebugLevel, log.GetLevel())
	})

	t.Run("empty name is a 400 carrying the valid names", func(t *testing.T) {
		cfg, log := newCfg()
		outcome := cfg.ApplyLevel("")
		assert.Equal(t, http.StatusBadRequest, outcome.StatusCode)
		require.NotNil(t, outcome.Body)
		assert.Equal(t, "level is required", outcome.Body.Message)
		assert.Equal(t, logkit.ValidLevelStrings(), outcome.Body.ValidLevels)
		assert.Empty(t, outcome.Body.Level, "a rejected request must not claim a level")
		assert.Equal(t, logkit.InfoLevel, log.GetLevel(), "level must be untouched")
	})

	t.Run("unparseable name is a 400 carrying the valid names", func(t *testing.T) {
		cfg, log := newCfg()
		outcome := cfg.ApplyLevel("shout")
		assert.Equal(t, http.StatusBadRequest, outcome.StatusCode)
		require.NotNil(t, outcome.Body)
		assert.NotEmpty(t, outcome.Body.Message)
		assert.Equal(t, logkit.ValidLevelStrings(), outcome.Body.ValidLevels)
		assert.Equal(t, logkit.InfoLevel, log.GetLevel(), "level must be untouched")
	})

	t.Run("every advertised level name is accepted", func(t *testing.T) {
		for _, name := range logkit.ValidLevelStrings() {
			cfg, _ := newCfg()
			outcome := cfg.ApplyLevel(name)
			assert.Equal(t, http.StatusOK, outcome.StatusCode, "level %q is advertised but rejected", name)
		}
	})
}

func TestLevelHandlerConfig_MaxBody(t *testing.T) {
	assert.Equal(t, int64(logkit.DefaultLevelMaxBodyBytes), logkit.LevelHandlerConfig{}.MaxBody())
	assert.Equal(t, int64(logkit.DefaultLevelMaxBodyBytes), logkit.LevelHandlerConfig{MaxBodyBytes: 0}.MaxBody())
	assert.Equal(t, int64(logkit.DefaultLevelMaxBodyBytes), logkit.LevelHandlerConfig{MaxBodyBytes: -1}.MaxBody())
	assert.Equal(t, int64(64), logkit.LevelHandlerConfig{MaxBodyBytes: 64}.MaxBody())
}

func TestMiddlewareConfig_Normalized(t *testing.T) {
	t.Run("fills in the defaults an adapter relies on", func(t *testing.T) {
		cfg := logkit.MiddlewareConfig{}.Normalized()
		assert.NotNil(t, cfg.Logger)
		assert.Equal(t, "X-Request-ID", cfg.RequestIDHeader)
		assert.Equal(t, 1024, cfg.MaxBodySize)
		assert.Equal(t, logkit.InfoLevel, cfg.LogLevel)
		assert.Equal(t, logkit.WarnLevel, cfg.WarnLevel)
		assert.Equal(t, logkit.ErrorLevel, cfg.ErrorLevel)
		assert.Equal(t, logkit.DefaultMiddlewareConfig().SensitiveHeaders, cfg.SensitiveHeaders)
	})

	t.Run("keeps explicit values", func(t *testing.T) {
		var buf bytes.Buffer
		log := logkit.New(logkit.Config{Output: &buf, Format: logkit.FormatJSON})
		cfg := logkit.MiddlewareConfig{
			Logger:           log,
			RequestIDHeader:  "X-Trace",
			MaxBodySize:      7,
			LogLevel:         logkit.ErrorLevel,
			SensitiveHeaders: []string{"X-Mine"},
		}.Normalized()
		assert.Same(t, log, cfg.Logger)
		assert.Equal(t, "X-Trace", cfg.RequestIDHeader)
		assert.Equal(t, 7, cfg.MaxBodySize)
		assert.Equal(t, logkit.ErrorLevel, cfg.LogLevel)
		assert.Equal(t, []string{"X-Mine"}, cfg.SensitiveHeaders)
	})

	t.Run("a negative MaxBodySize falls back to the default", func(t *testing.T) {
		assert.Equal(t, 1024, logkit.MiddlewareConfig{MaxBodySize: -5}.Normalized().MaxBodySize)
	})

	t.Run("an intentional all-debug config survives", func(t *testing.T) {
		// All three at their zero value reads as "unset", so a caller who
		// really wants debug for every status has to say so on at least one
		// field. Pinning the documented escape hatch.
		cfg := logkit.MiddlewareConfig{
			LogLevel:   logkit.DebugLevel,
			WarnLevel:  logkit.DebugLevel,
			ErrorLevel: logkit.TraceLevel,
		}.Normalized()
		assert.Equal(t, logkit.DebugLevel, cfg.LogLevel)
		assert.Equal(t, logkit.DebugLevel, cfg.WarnLevel)
		assert.Equal(t, logkit.TraceLevel, cfg.ErrorLevel)
	})

	t.Run("is idempotent", func(t *testing.T) {
		once := logkit.MiddlewareConfig{}.Normalized()
		twice := once.Normalized()
		assert.Equal(t, once.RequestIDHeader, twice.RequestIDHeader)
		assert.Equal(t, once.MaxBodySize, twice.MaxBodySize)
		assert.Equal(t, once.LogLevel, twice.LogLevel)
		assert.Equal(t, once.WarnLevel, twice.WarnLevel)
		assert.Equal(t, once.ErrorLevel, twice.ErrorLevel)
		assert.Equal(t, once.SensitiveHeaders, twice.SensitiveHeaders)
	})

	t.Run("does not mutate the receiver", func(t *testing.T) {
		original := logkit.MiddlewareConfig{}
		_ = original.Normalized()
		assert.Nil(t, original.Logger)
		assert.Empty(t, original.RequestIDHeader)
		assert.Zero(t, original.MaxBodySize)
	})
}

func TestMiddlewareConfig_SkipPathSet(t *testing.T) {
	set := logkit.MiddlewareConfig{SkipPaths: []string{"/health", "/metrics"}}.SkipPathSet()
	assert.True(t, set["/health"])
	assert.True(t, set["/metrics"])
	assert.False(t, set["/other"])
	assert.Len(t, set, 2)

	assert.Empty(t, logkit.MiddlewareConfig{}.SkipPathSet())
}

func TestMiddlewareConfig_SensitiveHeaderSet(t *testing.T) {
	t.Run("lower-cases the configured names", func(t *testing.T) {
		set := logkit.MiddlewareConfig{SensitiveHeaders: []string{"X-My-Secret", "authorization"}}.SensitiveHeaderSet()
		assert.True(t, set["x-my-secret"])
		assert.True(t, set["authorization"])
		assert.False(t, set["X-My-Secret"])
	})

	t.Run("reads the normalized defaults", func(t *testing.T) {
		set := logkit.MiddlewareConfig{}.Normalized().SensitiveHeaderSet()
		for _, name := range []string{"authorization", "x-api-key", "x-signature", "cookie", "set-cookie"} {
			assert.True(t, set[name], "%s should be redacted by default", name)
		}
	})
}

func TestMiddlewareConfig_SensitiveBodyKeys(t *testing.T) {
	t.Run("falls back to the package defaults", func(t *testing.T) {
		keys := logkit.MiddlewareConfig{}.SensitiveBodyKeys()
		assert.Contains(t, keys, "password")
		assert.Contains(t, keys, "access_token")
	})

	t.Run("an explicit list replaces the defaults", func(t *testing.T) {
		keys := logkit.MiddlewareConfig{SensitiveBodyFields: []string{"ssn"}}.SensitiveBodyKeys()
		assert.Equal(t, []string{"ssn"}, keys)
	})
}

func TestMiddlewareConfig_SensitiveQueryKeys(t *testing.T) {
	t.Run("falls back to the package defaults", func(t *testing.T) {
		keys := logkit.MiddlewareConfig{}.SensitiveQueryKeys()
		assert.Contains(t, keys, "password")
		assert.Contains(t, keys, "token")
	})

	t.Run("an explicit list replaces the defaults", func(t *testing.T) {
		keys := logkit.MiddlewareConfig{SensitiveQueryParams: []string{"sid"}}.SensitiveQueryKeys()
		assert.Equal(t, []string{"sid"}, keys)
	})

	t.Run("DisableQueryRedaction wins over an explicit list", func(t *testing.T) {
		keys := logkit.MiddlewareConfig{
			SensitiveQueryParams:  []string{"sid"},
			DisableQueryRedaction: true,
		}.SensitiveQueryKeys()
		assert.Nil(t, keys)
	})

	t.Run("an empty list means defaults, not off", func(t *testing.T) {
		// The JSON/YAML round-trip trap: an omitted field unmarshals to nil,
		// and nil must not read as "redaction disabled".
		keys := logkit.MiddlewareConfig{SensitiveQueryParams: nil}.SensitiveQueryKeys()
		assert.NotEmpty(t, keys)
	})
}

func TestRedactQuery_UnparseableInput(t *testing.T) {
	// A query Go cannot parse must not be logged verbatim: it could hold the
	// very token the caller asked to redact.
	out := logkit.RedactQuery("%zz=1&token=secret", []string{"token"})
	assert.Equal(t, "[UNPARSEABLE QUERY REDACTED]", out)
	assert.NotContains(t, out, "secret")
}

func TestRedactQuery_NoKeysIsPassThrough(t *testing.T) {
	assert.Equal(t, "", logkit.RedactQuery("", []string{"token"}))
	assert.Equal(t, "a=1&token=x", logkit.RedactQuery("a=1&token=x", nil))
}

func TestRedactBody_EmptyBody(t *testing.T) {
	assert.Equal(t, "", logkit.RedactBody("application/json", nil, []string{"password"}))
	assert.Equal(t, "", logkit.RedactBody("application/json", []byte{}, []string{"password"}))
}

func TestRedactBody_UnparseableForm(t *testing.T) {
	out := logkit.RedactBody(
		"application/x-www-form-urlencoded",
		[]byte("%zz=1&password=hunter2"),
		[]string{"password"},
	)
	assert.Equal(t, "[UNPARSEABLE FORM BODY REDACTED]", out)
	assert.NotContains(t, out, "hunter2")
}

func TestNewRequestID_IsAUniqueUUID(t *testing.T) {
	first := logkit.NewRequestID()
	second := logkit.NewRequestID()
	assert.NotEqual(t, first, second)
	assert.Len(t, first, 36)
}
