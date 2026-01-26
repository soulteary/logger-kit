package logger

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestFormat_String(t *testing.T) {
	tests := []struct {
		format   Format
		expected string
	}{
		{FormatJSON, "json"},
		{FormatConsole, "console"},
		{Format(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.format.String())
		})
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected Format
	}{
		{"console", FormatConsole},
		{"text", FormatConsole},
		{"pretty", FormatConsole},
		{"json", FormatJSON},
		{"", FormatJSON},
		{"unknown", FormatJSON},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseFormat(tt.input))
		})
	}
}

func TestDefaultConsoleWriterConfig(t *testing.T) {
	cfg := DefaultConsoleWriterConfig()

	assert.Equal(t, os.Stderr, cfg.Out)
	assert.Equal(t, time.Kitchen, cfg.TimeFormat)
	assert.False(t, cfg.NoColor)
}

func TestNewConsoleWriter(t *testing.T) {
	var buf bytes.Buffer
	cw := NewConsoleWriter(ConsoleWriterConfig{
		Out:        &buf,
		TimeFormat: time.RFC3339,
		NoColor:    true,
	})

	assert.NotNil(t, cw)
	assert.Equal(t, &buf, cw.Out)
	assert.Equal(t, time.RFC3339, cw.TimeFormat)
	assert.True(t, cw.NoColor)
}

func TestNewConsoleWriter_Defaults(t *testing.T) {
	cw := NewConsoleWriter(ConsoleWriterConfig{})

	assert.NotNil(t, cw)
	assert.Equal(t, os.Stderr, cw.Out)
	assert.Equal(t, time.Kitchen, cw.TimeFormat)
}

func TestNewConsoleWriter_WithCustomFormatFieldValue(t *testing.T) {
	var buf bytes.Buffer
	customFormatter := func(i interface{}) string {
		return "[CUSTOM]"
	}

	cw := NewConsoleWriter(ConsoleWriterConfig{
		Out:              &buf,
		TimeFormat:       time.RFC3339,
		NoColor:          true,
		FormatFieldValue: customFormatter,
	})

	assert.NotNil(t, cw)
	// Verify the custom formatter is used
	result := cw.FormatFieldValue("test")
	assert.Equal(t, "[CUSTOM]", result)
}

func TestNewConsoleWriter_WithAllOptions(t *testing.T) {
	var buf bytes.Buffer
	cw := NewConsoleWriter(ConsoleWriterConfig{
		Out:           &buf,
		TimeFormat:    time.RFC3339,
		NoColor:       true,
		PartsOrder:    []string{"level", "message"},
		PartsExclude:  []string{"time"},
		FieldsOrder:   []string{"field1", "field2"},
		FieldsExclude: []string{"secret"},
	})

	assert.NotNil(t, cw)
	assert.Equal(t, []string{"level", "message"}, cw.PartsOrder)
	assert.Equal(t, []string{"time"}, cw.PartsExclude)
	assert.Equal(t, []string{"field1", "field2"}, cw.FieldsOrder)
	assert.Equal(t, []string{"secret"}, cw.FieldsExclude)
}

func TestNewConsoleWriter_DefaultFormatFieldValue(t *testing.T) {
	var buf bytes.Buffer
	// Create console writer without custom FormatFieldValue
	cw := NewConsoleWriter(ConsoleWriterConfig{
		Out:        &buf,
		TimeFormat: time.RFC3339,
		NoColor:    true,
	})

	// Test with string value
	result := cw.FormatFieldValue("test_value")
	assert.Equal(t, "test_value", result)

	// Test with nil value
	result = cw.FormatFieldValue(nil)
	assert.Equal(t, "null", result)

	// Test with non-string value
	result = cw.FormatFieldValue(123)
	assert.Equal(t, "123", result)

	// Test with complex value
	result = cw.FormatFieldValue(map[string]int{"a": 1})
	assert.Contains(t, result, "a")
}

func TestMultiWriter(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	writer := MultiWriter(&buf1, &buf2)

	assert.NotNil(t, writer)
}

func TestLevelWriter_WriteLevel(t *testing.T) {
	var buf bytes.Buffer
	lw := LevelWriter{
		Writer: &buf,
		Level:  WarnLevel,
	}

	// Write at warn level - should be written
	n, err := lw.WriteLevel(WarnLevel.ToZerolog(), []byte("warn message"))
	assert.NoError(t, err)
	assert.Equal(t, len("warn message"), n)
	assert.Equal(t, "warn message", buf.String())

	buf.Reset()

	// Write at info level - should be filtered
	n, err = lw.WriteLevel(InfoLevel.ToZerolog(), []byte("info message"))
	assert.NoError(t, err)
	assert.Equal(t, len("info message"), n)
	assert.Empty(t, buf.String())

	buf.Reset()

	// Write at error level - should be written
	n, err = lw.WriteLevel(ErrorLevel.ToZerolog(), []byte("error message"))
	assert.NoError(t, err)
	assert.Equal(t, len("error message"), n)
	assert.Equal(t, "error message", buf.String())
}

func TestFilteredMultiWriter(t *testing.T) {
	var infoBuf, errorBuf bytes.Buffer

	writers := []LevelWriter{
		{Writer: &infoBuf, Level: InfoLevel},
		{Writer: &errorBuf, Level: ErrorLevel},
	}

	writer := FilteredMultiWriter(writers...)
	assert.NotNil(t, writer)
}

func TestTimeFormatPresets(t *testing.T) {
	// Unix is empty string in zerolog (special value for Unix timestamp)
	assert.Equal(t, "", TimeFormatPresets.Unix)
	assert.NotEmpty(t, TimeFormatPresets.UnixMs)
	assert.NotEmpty(t, TimeFormatPresets.UnixMicro)
	assert.NotEmpty(t, TimeFormatPresets.UnixNano)
	assert.NotEmpty(t, TimeFormatPresets.RFC3339)
	assert.NotEmpty(t, TimeFormatPresets.RFC3339Ms)
	assert.NotEmpty(t, TimeFormatPresets.Kitchen)
	assert.NotEmpty(t, TimeFormatPresets.DateTime)
	assert.NotEmpty(t, TimeFormatPresets.DateOnly)
	assert.NotEmpty(t, TimeFormatPresets.TimeOnly)
}

func TestDefaultFieldNames(t *testing.T) {
	fn := DefaultFieldNames()

	assert.NotEmpty(t, fn.Time)
	assert.NotEmpty(t, fn.Level)
	assert.NotEmpty(t, fn.Message)
	assert.NotEmpty(t, fn.Error)
	assert.NotEmpty(t, fn.Caller)
	assert.NotEmpty(t, fn.Stack)
}

func TestFieldNames_Apply(t *testing.T) {
	// Save original values
	origTime := zerolog.TimestampFieldName
	origLevel := zerolog.LevelFieldName
	origMessage := zerolog.MessageFieldName
	origError := zerolog.ErrorFieldName
	origCaller := zerolog.CallerFieldName
	origStack := zerolog.ErrorStackFieldName

	// Restore original values after test
	defer func() {
		zerolog.TimestampFieldName = origTime
		zerolog.LevelFieldName = origLevel
		zerolog.MessageFieldName = origMessage
		zerolog.ErrorFieldName = origError
		zerolog.CallerFieldName = origCaller
		zerolog.ErrorStackFieldName = origStack
	}()

	fn := FieldNames{
		Time:    "ts",
		Level:   "lvl",
		Message: "msg",
		Error:   "err",
		Caller:  "caller",
		Stack:   "stack",
	}

	// Should not panic
	assert.NotPanics(t, func() {
		fn.Apply()
	})

	// Verify fields were applied
	assert.Equal(t, "ts", zerolog.TimestampFieldName)
	assert.Equal(t, "lvl", zerolog.LevelFieldName)
	assert.Equal(t, "msg", zerolog.MessageFieldName)
	assert.Equal(t, "err", zerolog.ErrorFieldName)
	assert.Equal(t, "caller", zerolog.CallerFieldName)
	assert.Equal(t, "stack", zerolog.ErrorStackFieldName)
}

func TestLogger_ConsoleFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatConsole,
	})

	logger.Info().Msg("test message")

	output := buf.String()
	assert.NotEmpty(t, output)
	assert.Contains(t, output, "test message")
}

func TestLogger_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  InfoLevel,
		Output: &buf,
		Format: FormatJSON,
	})

	logger.Info().Msg("test message")

	output := buf.String()
	assert.NotEmpty(t, output)
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "level")
}
