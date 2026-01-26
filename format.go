package logger

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Format represents the log output format.
type Format int

const (
	// FormatJSON outputs logs in JSON format.
	FormatJSON Format = iota

	// FormatConsole outputs logs in human-readable console format.
	FormatConsole
)

// String returns the string representation of the format.
func (f Format) String() string {
	switch f {
	case FormatJSON:
		return "json"
	case FormatConsole:
		return "console"
	default:
		return "unknown"
	}
}

// ParseFormat parses a string into a Format.
func ParseFormat(s string) Format {
	switch s {
	case "console", "text", "pretty":
		return FormatConsole
	default:
		return FormatJSON
	}
}

// ConsoleWriterConfig configures the console writer.
type ConsoleWriterConfig struct {
	// Out is the output destination.
	// Default: os.Stderr
	Out io.Writer

	// TimeFormat is the format for timestamps.
	// Default: time.Kitchen
	TimeFormat string

	// NoColor disables colored output.
	// Default: false
	NoColor bool

	// PartsOrder defines the order of parts in output.
	// Default: ["time", "level", "caller", "message"]
	PartsOrder []string

	// PartsExclude defines parts to exclude from output.
	PartsExclude []string

	// FieldsOrder defines the order of additional fields.
	FieldsOrder []string

	// FieldsExclude defines fields to exclude from output.
	FieldsExclude []string

	// FormatTimestamp is a custom formatter for timestamp.
	FormatTimestamp zerolog.Formatter

	// FormatLevel is a custom formatter for level.
	FormatLevel zerolog.Formatter

	// FormatCaller is a custom formatter for caller.
	FormatCaller zerolog.Formatter

	// FormatMessage is a custom formatter for message.
	FormatMessage zerolog.Formatter

	// FormatFieldName is a custom formatter for field names.
	FormatFieldName zerolog.Formatter

	// FormatFieldValue is a custom formatter for field values.
	FormatFieldValue zerolog.Formatter

	// FormatErrFieldName is a custom formatter for error field name.
	FormatErrFieldName zerolog.Formatter

	// FormatErrFieldValue is a custom formatter for error field value.
	FormatErrFieldValue zerolog.Formatter
}

// DefaultConsoleWriterConfig returns the default console writer configuration.
func DefaultConsoleWriterConfig() ConsoleWriterConfig {
	return ConsoleWriterConfig{
		Out:        os.Stderr,
		TimeFormat: time.Kitchen,
		NoColor:    false,
	}
}

// NewConsoleWriter creates a new console writer with the given configuration.
func NewConsoleWriter(cfg ConsoleWriterConfig) zerolog.ConsoleWriter {
	if cfg.Out == nil {
		cfg.Out = os.Stderr
	}
	if cfg.TimeFormat == "" {
		cfg.TimeFormat = time.Kitchen
	}

	cw := zerolog.ConsoleWriter{
		Out:             cfg.Out,
		TimeFormat:      cfg.TimeFormat,
		NoColor:         cfg.NoColor,
		PartsOrder:      cfg.PartsOrder,
		PartsExclude:    cfg.PartsExclude,
		FieldsOrder:     cfg.FieldsOrder,
		FieldsExclude:   cfg.FieldsExclude,
		FormatTimestamp: cfg.FormatTimestamp,
		FormatLevel:     cfg.FormatLevel,
		FormatCaller:    cfg.FormatCaller,
		FormatMessage:   cfg.FormatMessage,
		FormatFieldName: cfg.FormatFieldName,
		FormatFieldValue: func(i interface{}) string {
			if cfg.FormatFieldValue != nil {
				return cfg.FormatFieldValue(i)
			}
			// Default: convert to string using fmt
			if i == nil {
				return "null"
			}
			switch v := i.(type) {
			case string:
				return v
			default:
				return fmt.Sprintf("%v", i)
			}
		},
		FormatErrFieldName:  cfg.FormatErrFieldName,
		FormatErrFieldValue: cfg.FormatErrFieldValue,
	}

	return cw
}

// MultiWriter creates an io.Writer that writes to multiple writers.
func MultiWriter(writers ...io.Writer) io.Writer {
	return zerolog.MultiLevelWriter(writers...)
}

// LevelWriter wraps a writer to only write at or above a certain level.
type LevelWriter struct {
	io.Writer
	Level Level
}

// WriteLevel implements zerolog.LevelWriter.
func (lw LevelWriter) WriteLevel(l zerolog.Level, p []byte) (n int, err error) {
	if l >= lw.Level.ToZerolog() {
		return lw.Write(p)
	}
	return len(p), nil
}

// FilteredMultiWriter creates a writer that routes logs to different outputs based on level.
// For example, you can send error+ logs to a file and info+ logs to stdout.
func FilteredMultiWriter(writers ...LevelWriter) io.Writer {
	ws := make([]io.Writer, len(writers))
	for i, w := range writers {
		ws[i] = w
	}
	return zerolog.MultiLevelWriter(ws...)
}

// TimeFormatPresets provides common time format presets.
var TimeFormatPresets = struct {
	Unix      string
	UnixMs    string
	UnixMicro string
	UnixNano  string
	RFC3339   string
	RFC3339Ms string
	Kitchen   string
	DateTime  string
	DateOnly  string
	TimeOnly  string
}{
	Unix:      zerolog.TimeFormatUnix,
	UnixMs:    zerolog.TimeFormatUnixMs,
	UnixMicro: zerolog.TimeFormatUnixMicro,
	UnixNano:  zerolog.TimeFormatUnixNano,
	RFC3339:   time.RFC3339,
	RFC3339Ms: "2006-01-02T15:04:05.000Z07:00",
	Kitchen:   time.Kitchen,
	DateTime:  time.DateTime,
	DateOnly:  time.DateOnly,
	TimeOnly:  time.TimeOnly,
}

// SetFieldNames configures the field names used in log output.
type FieldNames struct {
	Time      string
	Level     string
	Message   string
	Error     string
	Caller    string
	Stack     string
	Timestamp string
}

// DefaultFieldNames returns the default field names.
func DefaultFieldNames() FieldNames {
	return FieldNames{
		Time:      zerolog.TimestampFieldName,
		Level:     zerolog.LevelFieldName,
		Message:   zerolog.MessageFieldName,
		Error:     zerolog.ErrorFieldName,
		Caller:    zerolog.CallerFieldName,
		Stack:     zerolog.ErrorStackFieldName,
		Timestamp: zerolog.TimestampFieldName,
	}
}

// Apply sets the zerolog global field names.
func (fn FieldNames) Apply() {
	if fn.Time != "" {
		zerolog.TimestampFieldName = fn.Time
	}
	if fn.Level != "" {
		zerolog.LevelFieldName = fn.Level
	}
	if fn.Message != "" {
		zerolog.MessageFieldName = fn.Message
	}
	if fn.Error != "" {
		zerolog.ErrorFieldName = fn.Error
	}
	if fn.Caller != "" {
		zerolog.CallerFieldName = fn.Caller
	}
	if fn.Stack != "" {
		zerolog.ErrorStackFieldName = fn.Stack
	}
}
