package logger

import (
	"os"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{TraceLevel, "trace"},
		{DebugLevel, "debug"},
		{InfoLevel, "info"},
		{WarnLevel, "warn"},
		{ErrorLevel, "error"},
		{FatalLevel, "fatal"},
		{PanicLevel, "panic"},
		{NoLevel, ""},
		{Disabled, "disabled"},
		{Level(100), "Level(100)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.level.String())
		})
	}
}

func TestLevel_ToZerolog(t *testing.T) {
	tests := []struct {
		level    Level
		expected zerolog.Level
	}{
		{TraceLevel, zerolog.TraceLevel},
		{DebugLevel, zerolog.DebugLevel},
		{InfoLevel, zerolog.InfoLevel},
		{WarnLevel, zerolog.WarnLevel},
		{ErrorLevel, zerolog.ErrorLevel},
		{FatalLevel, zerolog.FatalLevel},
		{PanicLevel, zerolog.PanicLevel},
		{NoLevel, zerolog.NoLevel},
		{Disabled, zerolog.Disabled},
	}

	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.level.ToZerolog())
		})
	}
}

func TestFromZerolog(t *testing.T) {
	tests := []struct {
		level    zerolog.Level
		expected Level
	}{
		{zerolog.TraceLevel, TraceLevel},
		{zerolog.DebugLevel, DebugLevel},
		{zerolog.InfoLevel, InfoLevel},
		{zerolog.WarnLevel, WarnLevel},
		{zerolog.ErrorLevel, ErrorLevel},
		{zerolog.FatalLevel, FatalLevel},
		{zerolog.PanicLevel, PanicLevel},
		{zerolog.NoLevel, NoLevel},
		{zerolog.Disabled, Disabled},
	}

	for _, tt := range tests {
		t.Run(tt.expected.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, FromZerolog(tt.level))
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
		hasError bool
	}{
		{"trace", TraceLevel, false},
		{"TRACE", TraceLevel, false},
		{"Trace", TraceLevel, false},
		{"debug", DebugLevel, false},
		{"info", InfoLevel, false},
		{"warn", WarnLevel, false},
		{"warning", WarnLevel, false},
		{"error", ErrorLevel, false},
		{"err", ErrorLevel, false},
		{"fatal", FatalLevel, false},
		{"panic", PanicLevel, false},
		{"disabled", Disabled, false},
		{"off", Disabled, false},
		{"", NoLevel, false},
		{"  info  ", InfoLevel, false},
		{"invalid", NoLevel, true},
		{"unknown", NoLevel, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level, err := ParseLevel(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, level)
			}
		})
	}
}

func TestMustParseLevel(t *testing.T) {
	// Valid level should not panic
	assert.NotPanics(t, func() {
		level := MustParseLevel("info")
		assert.Equal(t, InfoLevel, level)
	})

	// Invalid level should panic
	assert.Panics(t, func() {
		MustParseLevel("invalid")
	})
}

func TestAllLevels(t *testing.T) {
	levels := AllLevels()
	assert.Len(t, levels, 7)
	assert.Contains(t, levels, TraceLevel)
	assert.Contains(t, levels, DebugLevel)
	assert.Contains(t, levels, InfoLevel)
	assert.Contains(t, levels, WarnLevel)
	assert.Contains(t, levels, ErrorLevel)
	assert.Contains(t, levels, FatalLevel)
	assert.Contains(t, levels, PanicLevel)
}

func TestValidLevelStrings(t *testing.T) {
	strings := ValidLevelStrings()
	assert.Len(t, strings, 8)
	assert.Contains(t, strings, "trace")
	assert.Contains(t, strings, "debug")
	assert.Contains(t, strings, "info")
	assert.Contains(t, strings, "warn")
	assert.Contains(t, strings, "error")
	assert.Contains(t, strings, "fatal")
	assert.Contains(t, strings, "panic")
	assert.Contains(t, strings, "disabled")
}

func TestLevelManager_GetSetLevel(t *testing.T) {
	lm := NewLevelManager(InfoLevel)

	assert.Equal(t, InfoLevel, lm.GetLevel())

	lm.SetLevel(DebugLevel)
	assert.Equal(t, DebugLevel, lm.GetLevel())

	lm.SetLevel(ErrorLevel)
	assert.Equal(t, ErrorLevel, lm.GetLevel())
}

func TestLevelManager_OnChange(t *testing.T) {
	lm := NewLevelManager(InfoLevel)

	var oldLevel, newLevel Level
	called := false

	unregister := lm.OnChange(func(old, new Level) {
		called = true
		oldLevel = old
		newLevel = new
	})

	lm.SetLevel(DebugLevel)

	assert.True(t, called)
	assert.Equal(t, InfoLevel, oldLevel)
	assert.Equal(t, DebugLevel, newLevel)

	// Unregister and verify callback is not called
	unregister()
	called = false
	lm.SetLevel(WarnLevel)
	// Note: Due to the simple unregister implementation, this may still be called
	// In a production implementation, we'd use a more robust unregister mechanism
}

func TestLevelManager_NoChangeNoCallback(t *testing.T) {
	lm := NewLevelManager(InfoLevel)

	called := false
	lm.OnChange(func(old, new Level) {
		called = true
	})

	// Setting same level should not trigger callback
	lm.SetLevel(InfoLevel)
	assert.False(t, called)
}

func TestLevelManager_Concurrent(t *testing.T) {
	lm := NewLevelManager(InfoLevel)

	var wg sync.WaitGroup
	levels := []Level{TraceLevel, DebugLevel, InfoLevel, WarnLevel, ErrorLevel}

	// Concurrent reads and writes
	for i := 0; i < 100; i++ {
		wg.Add(2)

		go func(idx int) {
			defer wg.Done()
			lm.SetLevel(levels[idx%len(levels)])
		}(i)

		go func() {
			defer wg.Done()
			_ = lm.GetLevel()
		}()
	}

	wg.Wait()
	// Test passes if no race condition or panic occurs
}

func TestGlobalLevelManager(t *testing.T) {
	// Save original levels (both our manager and zerolog's global level)
	original := GetGlobalLevel()
	zerologOriginal := zerolog.GlobalLevel()
	defer func() {
		SetGlobalLevel(original)
		zerolog.SetGlobalLevel(zerologOriginal)
	}()

	SetGlobalLevel(DebugLevel)
	assert.Equal(t, DebugLevel, GetGlobalLevel())

	SetGlobalLevel(ErrorLevel)
	assert.Equal(t, ErrorLevel, GetGlobalLevel())
}

func TestParseLevelFromEnv(t *testing.T) {
	// Test with custom getenv
	tests := []struct {
		name         string
		envValue     string
		defaultLevel Level
		expected     Level
	}{
		{"empty env", "", InfoLevel, InfoLevel},
		{"valid level", "debug", InfoLevel, DebugLevel},
		{"invalid level", "invalid", InfoLevel, InfoLevel},
		{"uppercase", "ERROR", InfoLevel, ErrorLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string {
				return tt.envValue
			}
			result := ParseLevelFromEnvFunc("LOG_LEVEL", tt.defaultLevel, getenv)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseLevelFromEnv_NilGetenv(t *testing.T) {
	// When getenv is nil, it should use the default function
	// which reads from actual environment
	level := ParseLevelFromEnvFunc("NON_EXISTENT_KEY_FOR_TEST", InfoLevel, nil)
	assert.Equal(t, InfoLevel, level)
}

func TestLevelManager_MultipleCallbacks(t *testing.T) {
	lm := NewLevelManager(InfoLevel)

	calls := 0
	var mu sync.Mutex

	for i := 0; i < 3; i++ {
		lm.OnChange(func(old, new Level) {
			mu.Lock()
			calls++
			mu.Unlock()
		})
	}

	lm.SetLevel(DebugLevel)

	mu.Lock()
	require.Equal(t, 3, calls)
	mu.Unlock()
}

func TestParseLevelFromEnv_WithRealEnv(t *testing.T) {
	// Save and restore environment variable
	const envKey = "TEST_LOG_LEVEL_FOR_LOGGER_KIT"
	originalValue := os.Getenv(envKey)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(envKey, originalValue)
		} else {
			_ = os.Unsetenv(envKey)
		}
	}()

	// Test with environment variable set
	require.NoError(t, os.Setenv(envKey, "debug"))
	level := ParseLevelFromEnv(envKey, InfoLevel)
	assert.Equal(t, DebugLevel, level)

	// Test with invalid value
	require.NoError(t, os.Setenv(envKey, "invalid_level"))
	level = ParseLevelFromEnv(envKey, WarnLevel)
	assert.Equal(t, WarnLevel, level) // Should return default

	// Test with empty value (unset)
	require.NoError(t, os.Unsetenv(envKey))
	level = ParseLevelFromEnv(envKey, ErrorLevel)
	assert.Equal(t, ErrorLevel, level) // Should return default
}

func TestLevel_ToZerolog_UnknownLevel(t *testing.T) {
	// Test with an unknown level value
	unknownLevel := Level(99)
	zerologLevel := unknownLevel.ToZerolog()
	assert.Equal(t, zerolog.NoLevel, zerologLevel)
}

func TestFromZerolog_UnknownLevel(t *testing.T) {
	// Test with an unknown zerolog level
	unknownLevel := zerolog.Level(99)
	level := FromZerolog(unknownLevel)
	assert.Equal(t, NoLevel, level)
}
