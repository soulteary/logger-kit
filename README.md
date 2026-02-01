# Logger Kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/logger-kit.svg)](https://pkg.go.dev/github.com/soulteary/logger-kit)
[![Go Report Card](https://goreportcard.com/badge/github.com/soulteary/logger-kit)](https://goreportcard.com/report/github.com/soulteary/logger-kit)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/soulteary/logger-kit/graph/badge.svg)](https://codecov.io/gh/soulteary/logger-kit)

[中文文档](README_CN.md)

A structured logging toolkit for Go applications based on [zerolog](https://github.com/rs/zerolog). Provides dynamic log level management, context-based logging, and HTTP endpoints for runtime log level adjustment.

## Features

- **zerolog Wrapper**: Structured logging with JSON and console output formats
- **Dynamic Log Level**: Thread-safe log level management with runtime adjustment
- **HTTP Endpoints**: RESTful API to get/set log levels at runtime
- **Context Logging**: Request ID, trace ID, span ID, and user ID propagation
- **Middleware**: Request logging middleware for both net/http and Fiber
- **Format Options**: JSON and human-readable console output

## Installation

```bash
go get github.com/soulteary/logger-kit
```

## Quick Start

### Basic Usage

```go
package main

import (
    "github.com/soulteary/logger-kit"
)

func main() {
    // Use default logger
    logger.Info().Msg("Application started")
    
    // With fields
    logger.Info().
        Str("user", "john").
        Int("attempt", 1).
        Msg("Login attempt")
    
    // With error
    logger.Error().
        Err(err).
        Str("operation", "database_query").
        Msg("Query failed")
}
```

### Custom Logger

```go
package main

import (
    "os"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    // Create custom logger
    log := logger.New(logger.Config{
        Level:          logger.DebugLevel,
        Output:         os.Stdout,
        Format:         logger.FormatJSON,
        ServiceName:    "my-service",
        ServiceVersion: "1.0.0",
        CallerEnabled:  true,
    })
    
    log.Info().Msg("Custom logger ready")
}
```

### Dynamic Log Level

```go
package main

import (
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    // Get current level
    currentLevel := log.GetLevel()
    
    // Change level at runtime
    log.SetLevel(logger.DebugLevel)
    
    // Register callback for level changes
    unregister := log.LevelManager().OnChange(func(old, new logger.Level) {
        fmt.Printf("Log level changed from %s to %s\n", old, new)
    })
    defer unregister()
}
```

### HTTP Endpoint for Log Level Management

```go
package main

import (
    "net/http"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    // Register log level endpoint
    mux := http.NewServeMux()
    logger.RegisterLevelEndpoint(mux, "/log/level", logger.LevelHandlerConfig{
        Logger: log,
        AllowedIPs: []string{"127.0.0.1"},
    })
    
    http.ListenAndServe(":8080", mux)
}

// GET /log/level - Get current log level
// PUT /log/level - Set log level (body: {"level": "debug"})
```

### Request Logging Middleware

#### net/http

```go
package main

import (
    "net/http"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    middleware := logger.Middleware(logger.MiddlewareConfig{
        Logger:           log,
        SkipPaths:        []string{"/health", "/metrics"},
        IncludeRequestID: true,
        IncludeLatency:   true,
        IncludeHeaders:   false, // Set to true to log headers
    })
    
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Access logger from context
        l := logger.LoggerFromRequest(r)
        l.Info().Msg("Processing request")
        
        // Access request ID
        requestID := logger.RequestIDFromRequest(r)
        
        w.Write([]byte("OK"))
    })
    
    http.ListenAndServe(":8080", middleware(handler))
}
```

#### Fiber

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    app := fiber.New()
    
    app.Use(logger.FiberMiddleware(logger.MiddlewareConfig{
        Logger:           log,
        SkipPaths:        []string{"/health"},
        IncludeRequestID: true,
    }))
    
    app.Get("/", func(c *fiber.Ctx) error {
        // Access logger from Fiber context
        l := logger.LoggerFromFiberCtx(c)
        l.Info().Msg("Processing request")
        
        return c.SendString("OK")
    })
    
    // Register log level endpoint
    logger.RegisterLevelEndpointFiber(app, "/log/level", logger.LevelHandlerConfig{
        Logger: log,
    })
    
    app.Listen(":3000")
}
```

### Context-Based Logging

```go
package main

import (
    "context"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    // Create context with logger and IDs
    ctx := context.Background()
    ctx = logger.ContextWithLogger(ctx, log)
    ctx = logger.ContextWithRequestID(ctx, "req-123")
    ctx = logger.ContextWithTraceID(ctx, "trace-456")
    ctx = logger.ContextWithUserID(ctx, "user-001")
    
    // Log with context - automatically includes all IDs
    l := logger.Ctx(ctx)
    l.Info().Msg("Processing request")
    // Output: {"level":"info","request_id":"req-123","trace_id":"trace-456","user_id":"user-001","message":"Processing request"}
}
```

### Console Format (Human-Readable)

```go
package main

import (
    "os"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.New(logger.Config{
        Level:  logger.InfoLevel,
        Output: os.Stdout,
        Format: logger.FormatConsole, // Human-readable format
    })
    
    log.Info().Str("user", "john").Msg("User logged in")
    // Output: 3:04PM INF User logged in user=john
}
```

### Parse Log Level from Environment

```go
package main

import (
    "github.com/soulteary/logger-kit"
)

func main() {
    // Read log level from LOG_LEVEL environment variable
    // Falls back to InfoLevel if not set or invalid
    level := logger.ParseLevelFromEnv("LOG_LEVEL", logger.InfoLevel)
    
    log := logger.New(logger.Config{
        Level: level,
    })
    
    log.Info().Msg("Logger initialized")
}
```

## API Reference

### Log Levels

| Level | Description |
|-------|-------------|
| `TraceLevel` | Most verbose level |
| `DebugLevel` | Debug messages |
| `InfoLevel` | Informational messages (default) |
| `WarnLevel` | Warning messages |
| `ErrorLevel` | Error messages |
| `FatalLevel` | Fatal messages (calls os.Exit(1)) |
| `PanicLevel` | Panic messages (panics) |
| `Disabled` | Disable logging |

### Configuration Options

```go
type Config struct {
    Level                Level     // Minimum log level (default: InfoLevel)
    Output               io.Writer // Log output (default: os.Stderr)
    Format               Format    // Output format: FormatJSON or FormatConsole
    TimeFormat           string    // Timestamp format
    CallerEnabled        bool      // Include caller information
    CallerSkipFrameCount int       // Skip frames for caller
    ServiceName          string    // Service name field
    ServiceVersion       string    // Version field
}
```

### Middleware Configuration

```go
type MiddlewareConfig struct {
    Logger            *Logger       // Logger instance
    SkipPaths         []string      // Paths to skip logging
    SkipFunc          func(*http.Request) bool // Custom skip function
    LogLevel          Level         // Level for 2xx responses
    WarnLevel         Level         // Level for 4xx responses
    ErrorLevel        Level         // Level for 5xx responses
    IncludeRequestID  bool          // Generate/propagate request ID
    RequestIDHeader   string        // Header name for request ID
    IncludeLatency    bool          // Log request duration
    IncludeHeaders    bool          // Log request headers
    SensitiveHeaders  []string      // Headers to redact
    IncludeQuery      bool          // Log query parameters
    IncludeBody       bool          // Log request body
    MaxBodySize       int           // Max body size to log
}
```

## Testing

```bash
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## License

Apache License 2.0
