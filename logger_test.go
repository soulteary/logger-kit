package logger

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, InfoLevel, cfg.Level)
	assert.Equal(t, os.Stderr, cfg.Output)
	assert.Equal(t, FormatJSON, cfg.Format)
}

func TestNew(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  DebugLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	assert.NotNil(t, logger)
	assert.Equal(t, DebugLevel, logger.GetLevel())
}

func TestNewDefault(t *testing.T) {
	logger := NewDefault()
	assert.NotNil(t, logger)
}

func TestLogger_SetLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	// Initially info level
	assert.Equal(t, InfoLevel, logger.GetLevel())

	// Change to debug
	logger.SetLevel(DebugLevel)
	assert.Equal(t, DebugLevel, logger.GetLevel())

	// Change to error
	logger.SetLevel(ErrorLevel)
	assert.Equal(t, ErrorLevel, logger.GetLevel())
}

func TestLogger_LogLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  TraceLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	tests := []struct {
		name  string
		log   func()
		level string
	}{
		{
			name:  "trace",
			log:   func() { logger.Trace().Msg("trace message") },
			level: "trace",
		},
		{
			name:  "debug",
			log:   func() { logger.Debug().Msg("debug message") },
			level: "debug",
		},
		{
			name:  "info",
			log:   func() { logger.Info().Msg("info message") },
			level: "info",
		},
		{
			name:  "warn",
			log:   func() { logger.Warn().Msg("warn message") },
			level: "warn",
		},
		{
			name:  "error",
			log:   func() { logger.Error().Msg("error message") },
			level: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.log()

			var result map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &result)
			require.NoError(t, err)

			assert.Equal(t, tt.level, result["level"])
		})
	}
}

func TestLogger_WithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	childLogger := logger.WithFields(map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	})

	childLogger.Info().Msg("test message")

	var result map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	assert.Equal(t, "value1", result["key1"])
	assert.Equal(t, float64(42), result["key2"])
}

func TestLogger_WithField(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	childLogger := logger.WithField("custom_key", "custom_value")
	childLogger.Info().Msg("test message")

	var result map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	assert.Equal(t, "custom_value", result["custom_key"])
}

func TestLogger_WithStr(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	childLogger := logger.WithStr("string_key", "string_value")
	childLogger.Info().Msg("test message")

	var result map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	assert.Equal(t, "string_value", result["string_key"])
}

func TestLogger_WithError(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	err := assert.AnError
	childLogger := logger.WithError(err)
	childLogger.Info().Msg("test message")

	var result map[string]interface{}
	parseErr := json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, parseErr)

	assert.Contains(t, result, "error")
}

func TestLogger_ServiceInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:          InfoLevel,
		Output:         &buf,
		Format:         FormatJSON,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	})

	logger.Info().Msg("test message")

	var result map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	assert.Equal(t, "test-service", result["service"])
	assert.Equal(t, "1.0.0", result["version"])
}

func TestLogger_Zerolog(t *testing.T) {
	logger := NewDefault()
	zl := logger.Zerolog()
	assert.NotNil(t, zl)
}

func TestLogger_LevelManager(t *testing.T) {
	logger := NewDefault()
	lm := logger.LevelManager()
	assert.NotNil(t, lm)
}

func TestDefault(t *testing.T) {
	logger := Default()
	assert.NotNil(t, logger)
}

func TestSetDefault(t *testing.T) {
	originalLogger := Default()
	defer SetDefault(originalLogger)

	var buf bytes.Buffer
	newLogger := New(Config{
		Level:  DebugLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	SetDefault(newLogger)
	assert.Equal(t, newLogger, Default())
}

func TestSetDefaultLevel(t *testing.T) {
	originalLevel := GetDefaultLevel()
	defer SetDefaultLevel(originalLevel)

	SetDefaultLevel(DebugLevel)
	assert.Equal(t, DebugLevel, GetDefaultLevel())
}

func TestPackageLevelFunctions(t *testing.T) {
	// Save and restore default logger
	origLogger := Default()
	defer SetDefault(origLogger)

	// Create a logger with TraceLevel to ensure all events are enabled
	SetDefault(New(Config{
		Level:  TraceLevel,
		Output: io.Discard,
		Format: FormatJSON,
	}))

	// These should not panic and return non-nil events
	assert.NotNil(t, Trace())
	assert.NotNil(t, Debug())
	assert.NotNil(t, Info())
	assert.NotNil(t, Warn())
	assert.NotNil(t, Error())
}

func TestLogger_Print(t *testing.T) {
	var buf bytes.Buffer
	// zerolog's Print uses Debug level, so we need TraceLevel or DebugLevel
	logger := New(Config{
		Level:  TraceLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	logger.Print("test message")
	assert.Contains(t, buf.String(), "test message")

	buf.Reset()
	logger.Printf("formatted %s", "message")
	assert.Contains(t, buf.String(), "formatted message")
}

func TestLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  WarnLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	// Debug and Info should be filtered
	logger.Debug().Msg("debug message")
	assert.Empty(t, buf.String())

	logger.Info().Msg("info message")
	assert.Empty(t, buf.String())

	// Warn and above should be logged
	logger.Warn().Msg("warn message")
	assert.NotEmpty(t, buf.String())
	assert.Contains(t, buf.String(), "warn message")
}

func TestLogger_Concurrent(t *testing.T) {
	// Use io.Discard which is thread-safe, unlike bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: io.Discard,
		Format: FormatJSON,
	})

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			logger.Info().Int("id", id).Msg("concurrent log")
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Test passes if no panic occurs
	assert.True(t, true)
}

func TestLogger_With(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	// Test With() method returns a zerolog.Context
	ctx := logger.With()
	assert.NotNil(t, ctx)

	// Use the context to add fields
	newLogger := ctx.Str("key", "value").Logger()
	newLogger.Info().Msg("test")

	assert.Contains(t, buf.String(), "key")
	assert.Contains(t, buf.String(), "value")
}

func TestLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  TraceLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	// Log() returns an event with no level
	logger.Log().Str("key", "value").Msg("no level log")

	assert.Contains(t, buf.String(), "no level log")
	assert.Contains(t, buf.String(), "key")
}

func TestNew_WithCaller(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:         InfoLevel,
		Output:        &buf,
		Format:        FormatJSON,
		CallerEnabled: true,
	})

	logger.Info().Msg("test with caller")

	assert.Contains(t, buf.String(), "caller")
}

func TestNew_WithCallerSkipFrameCount(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:                InfoLevel,
		Output:               &buf,
		Format:               FormatJSON,
		CallerEnabled:        true,
		CallerSkipFrameCount: 2,
	})

	logger.Info().Msg("test with caller skip")

	assert.Contains(t, buf.String(), "caller")
}

func TestNew_NilOutput(t *testing.T) {
	// When output is nil, it should default to os.Stderr
	logger := New(Config{
		Level:  InfoLevel,
		Output: nil,
		Format: FormatJSON,
	})

	assert.NotNil(t, logger)
}

func TestNew_EmptyTimeFormat(t *testing.T) {
	var buf bytes.Buffer
	// When TimeFormat is empty, it should default to Unix
	logger := New(Config{
		Level:      InfoLevel,
		Output:     &buf,
		Format:     FormatJSON,
		TimeFormat: "",
	})

	logger.Info().Msg("test")
	assert.NotEmpty(t, buf.String())
}

func TestPackageLevelFunctions_FatalPanic(t *testing.T) {
	// Save and restore default logger
	origLogger := Default()
	defer SetDefault(origLogger)

	// Create a logger with TraceLevel that writes to discard
	SetDefault(New(Config{
		Level:  TraceLevel,
		Output: io.Discard,
		Format: FormatJSON,
	}))

	// Fatal and Panic return events, we just verify they don't panic on creation
	// (we can't actually call .Msg() on them as they would exit/panic)
	fatalEvent := Fatal()
	assert.NotNil(t, fatalEvent)

	panicEvent := Panic()
	assert.NotNil(t, panicEvent)
}

func TestLogger_FatalPanic(t *testing.T) {
	logger := New(Config{
		Level:  TraceLevel,
		Output: io.Discard,
		Format: FormatJSON,
	})

	// Just verify the events are created without error
	fatalEvent := logger.Fatal()
	assert.NotNil(t, fatalEvent)

	panicEvent := logger.Panic()
	assert.NotNil(t, panicEvent)
}
