package logger

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

// Level represents a log level.
type Level int8

const (
	// TraceLevel is the most verbose level.
	TraceLevel Level = iota - 1

	// DebugLevel is for debug messages.
	DebugLevel

	// InfoLevel is for informational messages.
	InfoLevel

	// WarnLevel is for warning messages.
	WarnLevel

	// ErrorLevel is for error messages.
	ErrorLevel

	// FatalLevel is for fatal messages (logs and calls os.Exit(1)).
	FatalLevel

	// PanicLevel is for panic messages (logs and panics).
	PanicLevel

	// NoLevel means no level is set.
	NoLevel

	// Disabled disables the logger.
	Disabled
)

// String returns the string representation of the level.
func (l Level) String() string {
	switch l {
	case TraceLevel:
		return "trace"
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warn"
	case ErrorLevel:
		return "error"
	case FatalLevel:
		return "fatal"
	case PanicLevel:
		return "panic"
	case NoLevel:
		return ""
	case Disabled:
		return "disabled"
	default:
		return fmt.Sprintf("Level(%d)", l)
	}
}

// ToZerolog converts the Level to zerolog.Level.
func (l Level) ToZerolog() zerolog.Level {
	switch l {
	case TraceLevel:
		return zerolog.TraceLevel
	case DebugLevel:
		return zerolog.DebugLevel
	case InfoLevel:
		return zerolog.InfoLevel
	case WarnLevel:
		return zerolog.WarnLevel
	case ErrorLevel:
		return zerolog.ErrorLevel
	case FatalLevel:
		return zerolog.FatalLevel
	case PanicLevel:
		return zerolog.PanicLevel
	case NoLevel:
		return zerolog.NoLevel
	case Disabled:
		return zerolog.Disabled
	default:
		return zerolog.NoLevel
	}
}

// FromZerolog converts zerolog.Level to Level.
func FromZerolog(l zerolog.Level) Level {
	switch l {
	case zerolog.TraceLevel:
		return TraceLevel
	case zerolog.DebugLevel:
		return DebugLevel
	case zerolog.InfoLevel:
		return InfoLevel
	case zerolog.WarnLevel:
		return WarnLevel
	case zerolog.ErrorLevel:
		return ErrorLevel
	case zerolog.FatalLevel:
		return FatalLevel
	case zerolog.PanicLevel:
		return PanicLevel
	case zerolog.NoLevel:
		return NoLevel
	case zerolog.Disabled:
		return Disabled
	default:
		return NoLevel
	}
}

// ParseLevel parses a string into a Level.
// Returns an error if the string is not a valid level.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return TraceLevel, nil
	case "debug":
		return DebugLevel, nil
	case "info":
		return InfoLevel, nil
	case "warn", "warning":
		return WarnLevel, nil
	case "error", "err":
		return ErrorLevel, nil
	case "fatal":
		return FatalLevel, nil
	case "panic":
		return PanicLevel, nil
	case "disabled", "off":
		return Disabled, nil
	case "":
		return NoLevel, fmt.Errorf("empty log level")
	default:
		return NoLevel, fmt.Errorf("unknown log level: %s", s)
	}
}

// MustParseLevel is like ParseLevel but panics on error.
func MustParseLevel(s string) Level {
	l, err := ParseLevel(s)
	if err != nil {
		panic(err)
	}
	return l
}

// AllLevels returns all valid log levels.
func AllLevels() []Level {
	return []Level{
		TraceLevel,
		DebugLevel,
		InfoLevel,
		WarnLevel,
		ErrorLevel,
		FatalLevel,
		PanicLevel,
	}
}

// ValidLevelStrings returns all valid level strings.
func ValidLevelStrings() []string {
	return []string{
		"trace",
		"debug",
		"info",
		"warn",
		"error",
		"fatal",
		"panic",
		"disabled",
	}
}

// LevelManager provides thread-safe log level management.
type LevelManager struct {
	mu         sync.RWMutex
	level      Level
	onChange   []func(old, new Level)
	onChangeID []int64
	nextID     int64
}

// NewLevelManager creates a new LevelManager with the given initial level.
func NewLevelManager(initial Level) *LevelManager {
	return &LevelManager{
		level:      initial,
		onChange:   make([]func(old, new Level), 0),
		onChangeID: make([]int64, 0),
	}
}

// GetLevel returns the current log level.
func (m *LevelManager) GetLevel() Level {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.level
}

// SetLevel sets the log level and notifies all registered callbacks.
func (m *LevelManager) SetLevel(level Level) {
	m.mu.Lock()
	old := m.level
	m.level = level
	callbacks := make([]func(old, new Level), len(m.onChange))
	copy(callbacks, m.onChange)
	m.mu.Unlock()

	// Notify callbacks outside the lock
	if old != level {
		for _, cb := range callbacks {
			cb(old, level)
		}
	}
}

// OnChange registers a callback to be called when the level changes.
// Returns a function to unregister the callback.
func (m *LevelManager) OnChange(cb func(old, new Level)) func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextID
	m.nextID++
	m.onChange = append(m.onChange, cb)
	m.onChangeID = append(m.onChangeID, id)

	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		for i := range m.onChangeID {
			if m.onChangeID[i] == id {
				m.onChange = append(m.onChange[:i], m.onChange[i+1:]...)
				m.onChangeID = append(m.onChangeID[:i], m.onChangeID[i+1:]...)
				break
			}
		}
	}
}

// GlobalLevelManager is the global level manager used by the package.
var GlobalLevelManager = NewLevelManager(InfoLevel)

// SetGlobalLevel sets the global log level.
// This also sets the zerolog global level.
func SetGlobalLevel(level Level) {
	GlobalLevelManager.SetLevel(level)
	zerolog.SetGlobalLevel(level.ToZerolog())
}

// GetGlobalLevel returns the current global log level.
func GetGlobalLevel() Level {
	return GlobalLevelManager.GetLevel()
}

// ParseLevelFromEnv reads the log level from an environment variable.
// Returns defaultLevel if the variable is not set or invalid.
func ParseLevelFromEnv(envKey string, defaultLevel Level) Level {
	return ParseLevelFromEnvFunc(envKey, defaultLevel, nil)
}

// ParseLevelFromEnvFunc reads the log level from an environment variable using a custom getter.
// If getenv is nil, os.Getenv is used.
func ParseLevelFromEnvFunc(envKey string, defaultLevel Level, getenv func(string) string) Level {
	if getenv == nil {
		getenv = getEnvFunc
	}
	value := getenv(envKey)
	if value == "" {
		return defaultLevel
	}
	level, err := ParseLevel(value)
	if err != nil {
		return defaultLevel
	}
	return level
}

// getEnvFunc is the function used to get environment variables.
// Initialized to a placeholder, but overridden in env.go init().
var getEnvFunc func(string) string
