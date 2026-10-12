package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustedListEmptyTrustsNobody(t *testing.T) {
	for _, tt := range []struct {
		name string
		list []string
	}{
		{"nil", nil},
		{"empty", []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, isIPInTrustedList("192.0.2.1", tt.list))
		})
	}
}

func TestFilteredMultiWriterRoutesLogEvents(t *testing.T) {
	for _, tt := range []struct {
		name                string
		level               zerolog.Level
		wantInfo, wantError bool
	}{
		{"debug", zerolog.DebugLevel, false, false},
		{"info", zerolog.InfoLevel, true, false},
		{"warn", zerolog.WarnLevel, true, false},
		{"error", zerolog.ErrorLevel, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var infoBuf, errorBuf bytes.Buffer
			output := FilteredMultiWriter(
				LevelWriter{Writer: &infoBuf, Level: InfoLevel},
				LevelWriter{Writer: &errorBuf, Level: ErrorLevel},
			)
			l := zerolog.New(output).Level(zerolog.TraceLevel)
			l.WithLevel(tt.level).Msg("routed event")
			assertRegressionRoutedEvent(t, &infoBuf, tt.wantInfo, tt.name)
			assertRegressionRoutedEvent(t, &errorBuf, tt.wantError, tt.name)
		})
	}
}

func assertRegressionRoutedEvent(t *testing.T, buf *bytes.Buffer, want bool, level string) {
	t.Helper()
	if !want {
		assert.Empty(t, buf.String())
		return
	}
	var entry map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "routed event", entry["message"])
	assert.Equal(t, level, entry["level"])
}

type regressionErrorWriter struct {
	err   error
	calls int
}

func (w *regressionErrorWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, w.err
}

func TestFilteredMultiWriterPropagatesDestinationError(t *testing.T) {
	want := errors.New("destination unavailable")
	destination := &regressionErrorWriter{err: want}
	output := FilteredMultiWriter(LevelWriter{Writer: destination, Level: ErrorLevel})
	w, ok := output.(zerolog.LevelWriter)
	require.True(t, ok)
	payload := []byte("entry")

	n, err := w.WriteLevel(zerolog.WarnLevel, payload)
	require.NoError(t, err)
	assert.Equal(t, len(payload), n)
	assert.Zero(t, destination.calls, "filtered levels must not touch the destination")

	n, err = w.WriteLevel(zerolog.ErrorLevel, payload)
	assert.ErrorIs(t, err, want)
	assert.Zero(t, n)
	assert.Equal(t, 1, destination.calls)
}

func TestLevelManagerCancellationIsIdempotent(t *testing.T) {
	m := NewLevelManager(InfoLevel)
	firstCalls, secondCalls := 0, 0
	cancelFirst := m.OnChange(func(_, _ Level) { firstCalls++ })
	cancelSecond := m.OnChange(func(_, _ Level) { secondCalls++ })
	t.Cleanup(cancelSecond)
	cancelFirst()
	cancelFirst()
	m.SetLevel(WarnLevel)
	assert.Zero(t, firstCalls)
	assert.Equal(t, 1, secondCalls, "repeated cancellation must preserve other subscriptions")
	cancelSecond()
	cancelSecond()
	m.SetLevel(ErrorLevel)
	assert.Equal(t, 1, secondCalls)
}

func TestLevelManagerCallbackCanReadAndCancelItself(t *testing.T) {
	m := NewLevelManager(InfoLevel)
	var observed []Level
	var cancel func()
	cancel = m.OnChange(func(old, new Level) {
		observed = append(observed, old, new, m.GetLevel())
		cancel()
	})
	setRegressionLevelWithoutDeadlock(t, m, WarnLevel)
	assert.Equal(t, []Level{InfoLevel, WarnLevel, WarnLevel}, observed)
	setRegressionLevelWithoutDeadlock(t, m, ErrorLevel)
	assert.Equal(t, []Level{InfoLevel, WarnLevel, WarnLevel}, observed, "a callback that cancels itself must run only once")
	assert.Equal(t, ErrorLevel, m.GetLevel())
}

func setRegressionLevelWithoutDeadlock(t *testing.T, m *LevelManager, level Level) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.SetLevel(level)
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		t.Fatal("level change deadlocked while running a subscription callback")
	}
}

func TestMiddlewareRequestIDOptions(t *testing.T) {
	for _, tt := range []struct {
		name, incoming, generated string
		include                   bool
		wantContext, wantResponse string
		wantCalls                 int
	}{
		{name: "disabled without incoming ID"},
		{name: "disabled preserves incoming context", incoming: "incoming-id", wantContext: "incoming-id"},
		{name: "enabled preserves incoming ID", include: true, incoming: "incoming-id", wantContext: "incoming-id", wantResponse: "incoming-id"},
		{name: "enabled custom generator", include: true, generated: "generated-id", wantContext: "generated-id", wantResponse: "generated-id", wantCalls: 1},
		{name: "enabled empty generator", include: true, wantCalls: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			calls := 0
			cfg := MiddlewareConfig{
				Logger:           New(Config{Level: TraceLevel, Output: &buf}),
				IncludeRequestID: tt.include,
				RequestIDHeader:  "X-Correlation-ID",
				GenerateRequestID: func() string {
					calls++
					return tt.generated
				},
			}
			h := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.wantContext, RequestIDFromRequest(r))
				assert.Equal(t, tt.wantContext, r.Header.Get(cfg.RequestIDHeader))
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequest(http.MethodGet, "/request-id", nil)
			r.Header.Set(cfg.RequestIDHeader, tt.incoming)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(t, tt.wantResponse, w.Header().Get(cfg.RequestIDHeader))
			assert.Empty(t, w.Header().Get("X-Request-ID"))
			assert.Equal(t, tt.wantCalls, calls)
			var entry map[string]interface{}
			require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
			assertRegressionRequestID(t, entry, tt.wantResponse)
		})
	}
}

func assertRegressionRequestID(t *testing.T, entry map[string]interface{}, want string) {
	t.Helper()
	if want == "" {
		assert.NotContains(t, entry, "request_id")
		return
	}
	assert.Equal(t, want, entry["request_id"])
}

func TestRedactQueryPreservesRepeatedAndEscapedValues(t *testing.T) {
	raw := "ToKeN=s%26cret&ToKeN=other%2Bsecret&q=a%2Bb%20%26&q=x%2Fy&keep=alpha+beta"
	got := RedactQuery(raw, []string{" TOKEN "})
	values, err := url.ParseQuery(got)
	require.NoError(t, err)
	assert.Equal(t, url.Values{
		"ToKeN": {"***"},
		"q":     {"a+b &", "x/y"},
		"keep":  {"alpha beta"},
	}, values)
	assert.NotContains(t, got, "secret")
	assert.NotContains(t, got, "s%26cret")
}

func TestRedactJSONMatchesSensitiveKeysAtEveryDepth(t *testing.T) {
	body := []byte(`{"ToKeN":"secret-one","nested":{"api_KEY":"secret-two","keep":"雪☃"},"items":[{"toKEN":"secret-three"},true,null,42,"visible"],"normal":"safe\nline"}`)
	got := RedactBody(" Application/Problem+JSON ; charset=utf-8 ", body, []string{" TOKEN ", " api_key "})
	assert.JSONEq(t, `{"ToKeN":"***","nested":{"api_KEY":"***","keep":"雪☃"},"items":[{"toKEN":"***"},true,null,42,"visible"],"normal":"safe\nline"}`, got)
	assert.NotContains(t, got, "secret-")
}
