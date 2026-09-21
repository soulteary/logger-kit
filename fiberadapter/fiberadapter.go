// Package fiberadapter wires logger-kit into Fiber v3.
//
// It lives in its own package so that importing the root package does not drag
// Fiber -- and with it fasthttp -- into binaries that never use it. A service
// on net/http, Echo, Gin or chi pays nothing for Fiber support existing; only
// importing this package links it in.
//
// The rules that must not differ between frameworks -- the trusted-proxy rule
// behind ClientIP, query and body redaction, request-id generation -- live in
// the root package and are read from there.
package fiberadapter

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"

	logger "github.com/soulteary/logger-kit/v2"
)

// Source adapts a fiber.Ctx to logger.ClientIPSource.
type Source struct{ C fiber.Ctx }

// RemoteAddr is the direct peer address.
func (s Source) RemoteAddr() string { return s.C.RequestCtx().RemoteAddr().String() }

// Header returns a request header, or "" when absent.
func (s Source) Header(name string) string { return s.C.Get(name) }

// Config is logger.MiddlewareConfig plus the Fiber-typed hooks.
//
// SkipFunc and CustomFields cannot live on logger.MiddlewareConfig: fields
// typed func(fiber.Ctx) ... are exactly what pulled Fiber into the root
// package in the first place.
type Config struct {
	logger.MiddlewareConfig

	// SkipFunc skips logging for a request when it returns true.
	SkipFunc func(c fiber.Ctx) bool

	// CustomFields adds fields to each log entry.
	CustomFields func(c fiber.Ctx) map[string]interface{}
}

func resolve(config ...Config) (logger.MiddlewareConfig, func(fiber.Ctx) bool, func(fiber.Ctx) map[string]interface{}) {
	if len(config) == 0 {
		return logger.DefaultMiddlewareConfig(), nil, nil
	}
	return config[0].MiddlewareConfig, config[0].SkipFunc, config[0].CustomFields
}

type fiberContextKey uint8

const (
	fiberLoggerKey fiberContextKey = iota
	fiberRequestIDKey
)

// installRequestID resolves the request id, propagates it onto the request
// header, the response header and the Fiber locals, and returns it.
func installRequestID(c fiber.Ctx, cfg logger.MiddlewareConfig) string {
	requestID := c.Get(cfg.RequestIDHeader)
	if requestID == "" && cfg.IncludeRequestID {
		if cfg.GenerateRequestID != nil {
			requestID = cfg.GenerateRequestID()
		} else {
			requestID = logger.NewRequestID()
		}
		c.Request().Header.Set(cfg.RequestIDHeader, requestID)
	}
	if cfg.IncludeRequestID && requestID != "" {
		c.Set(cfg.RequestIDHeader, requestID)
	}
	if requestID != "" {
		c.Locals(fiberRequestIDKey, requestID)
	}
	return requestID
}

// redactedHeaders is the request's headers with the sensitive ones masked.
func redactedHeaders(c fiber.Ctx, sensitive map[string]bool) map[string]string {
	headers := make(map[string]string)
	for key, value := range c.Request().Header.All() {
		name := string(key)
		if sensitive[strings.ToLower(name)] {
			headers[name] = "[REDACTED]"
		} else {
			headers[name] = string(value)
		}
	}
	return headers
}

// Middleware creates a Fiber logging middleware.
func Middleware(config ...Config) fiber.Handler {
	cfg, skip, custom := resolve(config...)
	cfg = cfg.Normalized()
	skipPathMap := cfg.SkipPathSet()
	sensitiveHeaderMap := cfg.SensitiveHeaderSet()
	sensitiveBodyFields := cfg.SensitiveBodyKeys()

	return func(c fiber.Ctx) error {
		// Skip if the path is in the skip list, or the skip func says so
		if skipPathMap[c.Path()] || (skip != nil && skip(c)) {
			return c.Next()
		}

		start := time.Now()

		requestID := installRequestID(c, cfg)
		c.Locals(fiberLoggerKey, cfg.Logger)

		err := c.Next()

		fields := logger.RequestFields{
			Method:    c.Method(),
			Path:      c.Path(),
			Status:    c.Response().StatusCode(),
			ClientIP:  logger.ClientIP(Source{C: c}, cfg.TrustedProxies),
			UserAgent: c.Get("User-Agent"),
			RequestID: requestID,
			Latency:   time.Since(start),
			RawQuery:  string(c.Request().URI().QueryString()),
			Err:       err,
		}
		if cfg.IncludeHeaders {
			fields.Headers = redactedHeaders(c, sensitiveHeaderMap)
		}
		if cfg.IncludeBody {
			fields.Body = cfg.BodyForLog(c.Get("Content-Type"), c.Body(), sensitiveBodyFields)
		}
		if custom != nil {
			fields.Custom = custom(c)
		}

		cfg.LogRequest(fields)

		return err
	}
}

// Logger extracts the logger from Fiber context.
func Logger(c fiber.Ctx) *logger.Logger {
	if l, ok := c.Locals(fiberLoggerKey).(*logger.Logger); ok {
		return l
	}
	return logger.Default()
}

// RequestID extracts the request ID from Fiber context.
func RequestID(c fiber.Ctx) string {
	if id, ok := c.Locals(fiberRequestIDKey).(string); ok {
		return id
	}
	return ""
}

// Ctx returns a zerolog.Logger enriched with Fiber context values.
func Ctx(c fiber.Ctx) *zerolog.Logger {
	l := Logger(c)
	logger := l.Zerolog()

	if requestID := RequestID(c); requestID != "" {
		logger = logger.With().Str("request_id", requestID).Logger()
	}

	return &logger
}

// LevelHandlerConfig is logger.LevelHandlerConfig plus the Fiber-typed auth
// hook. AuthFunc cannot live on the root config: a func(fiber.Ctx) bool field
// is exactly what pulled Fiber into the root package.
type LevelHandlerConfig struct {
	logger.LevelHandlerConfig

	// AuthFunc authenticates a request; required when RequireAuth is set.
	AuthFunc func(c fiber.Ctx) bool
}

// LevelHandler returns a Fiber handler for reading and changing the log level.
// GET returns the current level; PUT/POST set a new one.
// It is the Fiber counterpart of logger.LevelHandler.
func LevelHandler(cfg LevelHandlerConfig) fiber.Handler {
	return func(c fiber.Ctx) error {
		if cfg.RequireAuth && cfg.AuthFunc == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "AuthFunc is required when RequireAuth is enabled",
			})
		}

		authenticated := !cfg.RequireAuth || cfg.AuthFunc(c)
		if denied := cfg.Authorize(Source{C: c}, authenticated); denied != nil {
			// JSON, as this handler has always answered; logger.LevelHandler
			// answers text/plain here. See logger.LevelOutcome.
			return c.Status(denied.StatusCode).JSON(fiber.Map{"error": denied.Error})
		}

		switch c.Method() {
		case fiber.MethodGet:
			return c.JSON(cfg.CurrentLevel().Body)

		case fiber.MethodPut, fiber.MethodPost:
			body := c.Body()
			if int64(len(body)) > cfg.MaxBody() {
				return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
					"error": "Request Entity Too Large",
				})
			}

			var req logger.LevelRequest
			if len(body) > 0 {
				_ = json.Unmarshal(body, &req)
			}
			if req.Level == "" {
				req.Level = c.Query("level")
			}

			outcome := cfg.ApplyLevel(req.Level)
			return c.Status(outcome.StatusCode).JSON(outcome.Body)

		default:
			return c.Status(fiber.StatusMethodNotAllowed).JSON(fiber.Map{
				"error": "Method Not Allowed",
			})
		}
	}
}

// RegisterLevelEndpoint registers the log level endpoint on a Fiber app.
// It is the Fiber counterpart of logger.RegisterLevelEndpoint.
func RegisterLevelEndpoint(app *fiber.App, path string, cfg LevelHandlerConfig) {
	handler := LevelHandler(cfg)
	app.Get(path, handler)
	app.Put(path, handler)
	app.Post(path, handler)
}
