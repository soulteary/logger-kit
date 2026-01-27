// Package logger provides structured logging functionality based on zerolog.
// It supports dynamic log level management, context-based logging, and HTTP endpoints
// for runtime log level adjustment.
package logger

import (
	"io"
	"os"

	"github.com/rs/zerolog"
)

// Config holds the logger configuration.
type Config struct {
	// Level is the minimum log level.
	// Default: InfoLevel
	Level Level

	// Output is the log output destination.
	// Default: os.Stderr
	Output io.Writer

	// Format specifies the log output format.
	// Default: FormatJSON
	Format Format

	// TimeFormat is the format for timestamp field.
	// Default: zerolog.TimeFormatUnix
	TimeFormat string

	// CallerEnabled enables caller information in logs.
	// Default: false
	CallerEnabled bool

	// CallerSkipFrameCount skips the specified number of frames when logging caller.
	// Default: 0
	CallerSkipFrameCount int

	// StackTraceEnabled enables stack trace for error logs.
	// Default: false
	StackTraceEnabled bool

	// ServiceName is added to every log entry if set.
	ServiceName string

	// ServiceVersion is added to every log entry if set.
	ServiceVersion string
}

// DefaultConfig returns the default logger configuration.
func DefaultConfig() Config {
	return Config{
		Level:      InfoLevel,
		Output:     os.Stderr,
		Format:     FormatJSON,
		TimeFormat: zerolog.TimeFormatUnix,
	}
}

// Logger wraps zerolog.Logger with additional functionality.
type Logger struct {
	zl      zerolog.Logger
	config  Config
	levelMg *LevelManager
}

// New creates a new Logger with the given configuration.
func New(cfg Config) *Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stderr
	}
	if cfg.TimeFormat == "" {
		cfg.TimeFormat = zerolog.TimeFormatUnix
	}

	// Set time format globally
	zerolog.TimeFieldFormat = cfg.TimeFormat

	// Create output based on format
	output := cfg.Output
	if cfg.Format == FormatConsole {
		output = zerolog.ConsoleWriter{
			Out:        cfg.Output,
			TimeFormat: cfg.TimeFormat,
			NoColor:    false,
		}
	}

	// Create base logger
	ctx := zerolog.New(output).With().Timestamp()

	// Add caller if enabled
	if cfg.CallerEnabled {
		if cfg.CallerSkipFrameCount > 0 {
			ctx = ctx.CallerWithSkipFrameCount(cfg.CallerSkipFrameCount)
		} else {
			ctx = ctx.Caller()
		}
	}

	// Add service info if provided
	if cfg.ServiceName != "" {
		ctx = ctx.Str("service", cfg.ServiceName)
	}
	if cfg.ServiceVersion != "" {
		ctx = ctx.Str("version", cfg.ServiceVersion)
	}

	zl := ctx.Logger().Level(cfg.Level.ToZerolog())

	return &Logger{
		zl:      zl,
		config:  cfg,
		levelMg: NewLevelManager(cfg.Level),
	}
}

// NewDefault creates a new Logger with default configuration.
func NewDefault() *Logger {
	return New(DefaultConfig())
}

// With returns a new Logger with the given fields added to the context.
func (l *Logger) With() zerolog.Context {
	return l.zl.With()
}

// WithFields returns a new Logger with the given fields.
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	ctx := l.zl.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return &Logger{
		zl:      ctx.Logger(),
		config:  l.config,
		levelMg: l.levelMg,
	}
}

// WithField returns a new Logger with the given field.
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{
		zl:      l.zl.With().Interface(key, value).Logger(),
		config:  l.config,
		levelMg: l.levelMg,
	}
}

// WithStr returns a new Logger with the given string field.
func (l *Logger) WithStr(key, value string) *Logger {
	return &Logger{
		zl:      l.zl.With().Str(key, value).Logger(),
		config:  l.config,
		levelMg: l.levelMg,
	}
}

// WithError returns a new Logger with the error field.
func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		zl:      l.zl.With().Err(err).Logger(),
		config:  l.config,
		levelMg: l.levelMg,
	}
}

// Zerolog returns the underlying zerolog.Logger.
func (l *Logger) Zerolog() zerolog.Logger {
	return l.zl
}

// ZerologPtr returns a pointer to the underlying zerolog.Logger for use with
// libraries that require *zerolog.Logger (e.g. middleware-kit).
func (l *Logger) ZerologPtr() *zerolog.Logger {
	return &l.zl
}

// LevelManager returns the level manager for this logger.
func (l *Logger) LevelManager() *LevelManager {
	return l.levelMg
}

// SetLevel sets the log level at runtime.
func (l *Logger) SetLevel(level Level) {
	l.levelMg.SetLevel(level)
	l.zl = l.zl.Level(level.ToZerolog())
}

// GetLevel returns the current log level.
func (l *Logger) GetLevel() Level {
	return l.levelMg.GetLevel()
}

// Trace logs a message at trace level.
func (l *Logger) Trace() *zerolog.Event {
	return l.zl.Trace()
}

// Debug logs a message at debug level.
func (l *Logger) Debug() *zerolog.Event {
	return l.zl.Debug()
}

// Info logs a message at info level.
func (l *Logger) Info() *zerolog.Event {
	return l.zl.Info()
}

// Warn logs a message at warn level.
func (l *Logger) Warn() *zerolog.Event {
	return l.zl.Warn()
}

// Error logs a message at error level.
func (l *Logger) Error() *zerolog.Event {
	return l.zl.Error()
}

// Fatal logs a message at fatal level.
func (l *Logger) Fatal() *zerolog.Event {
	return l.zl.Fatal()
}

// Panic logs a message at panic level.
func (l *Logger) Panic() *zerolog.Event {
	return l.zl.Panic()
}

// Log logs a message at the specified level.
func (l *Logger) Log() *zerolog.Event {
	return l.zl.Log()
}

// Print sends a log event with no level and no message.
func (l *Logger) Print(v ...interface{}) {
	l.zl.Print(v...)
}

// Printf sends a log event with no level and a formatted message.
func (l *Logger) Printf(format string, v ...interface{}) {
	l.zl.Printf(format, v...)
}

// Global logger instance
var defaultLogger = NewDefault()

// Default returns the default logger instance.
func Default() *Logger {
	return defaultLogger
}

// SetDefault sets the default logger instance.
func SetDefault(l *Logger) {
	defaultLogger = l
}

// SetDefaultLevel sets the log level of the default logger.
func SetDefaultLevel(level Level) {
	defaultLogger.SetLevel(level)
}

// GetDefaultLevel returns the current log level of the default logger.
func GetDefaultLevel() Level {
	return defaultLogger.GetLevel()
}

// Trace logs at trace level using the default logger.
func Trace() *zerolog.Event {
	return defaultLogger.Trace()
}

// Debug logs at debug level using the default logger.
func Debug() *zerolog.Event {
	return defaultLogger.Debug()
}

// Info logs at info level using the default logger.
func Info() *zerolog.Event {
	return defaultLogger.Info()
}

// Warn logs at warn level using the default logger.
func Warn() *zerolog.Event {
	return defaultLogger.Warn()
}

// Error logs at error level using the default logger.
func Error() *zerolog.Event {
	return defaultLogger.Error()
}

// Fatal logs at fatal level using the default logger.
func Fatal() *zerolog.Event {
	return defaultLogger.Fatal()
}

// Panic logs at panic level using the default logger.
func Panic() *zerolog.Event {
	return defaultLogger.Panic()
}
