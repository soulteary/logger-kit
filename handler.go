package logger

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// LevelHandlerConfig configures the log level HTTP endpoint.
type LevelHandlerConfig struct {
	// Logger is the logger instance to control.
	// If nil, the default logger is used.
	Logger *Logger

	// AllowedIPs is a list of IP addresses allowed to change the log level.
	// If empty, all IPs are allowed.
	AllowedIPs []string

	// RequireAuth enables authentication check.
	// If true, requests must pass the AuthFunc check.
	RequireAuth bool

	// AuthFunc is a custom authentication function.
	// Returns true if the request is authenticated.
	AuthFunc func(r *http.Request) bool

	// AuthFuncFiber is a custom authentication function for Fiber.
	// Returns true if the request is authenticated.
	AuthFuncFiber func(c *fiber.Ctx) bool
}

// DefaultLevelHandlerConfig returns the default configuration.
func DefaultLevelHandlerConfig() LevelHandlerConfig {
	return LevelHandlerConfig{
		Logger: nil, // Uses default logger
	}
}

// LevelResponse is the response structure for level endpoints.
type LevelResponse struct {
	Level         string   `json:"level"`
	ValidLevels   []string `json:"valid_levels,omitempty"`
	PreviousLevel string   `json:"previous_level,omitempty"`
	Message       string   `json:"message,omitempty"`
}

// LevelRequest is the request structure for changing log level.
type LevelRequest struct {
	Level string `json:"level"`
}

// LevelHandler returns an HTTP handler for managing log levels.
// GET: Returns the current log level.
// PUT/POST: Sets a new log level.
func LevelHandler(cfg LevelHandlerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		if cfg.RequireAuth && cfg.AuthFunc != nil {
			if !cfg.AuthFunc(r) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// Check allowed IPs
		if len(cfg.AllowedIPs) > 0 {
			clientIP := getClientIPStd(r)
			allowed := false
			for _, ip := range cfg.AllowedIPs {
				if ip == clientIP {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		logger := cfg.Logger
		if logger == nil {
			logger = defaultLogger
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodGet:
			// Return current level
			resp := LevelResponse{
				Level:       logger.GetLevel().String(),
				ValidLevels: ValidLevelStrings(),
			}
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

		case http.MethodPut, http.MethodPost:
			// Parse request
			var req LevelRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				// Try query parameter
				req.Level = r.URL.Query().Get("level")
			}

			if req.Level == "" {
				w.WriteHeader(http.StatusBadRequest)
				resp := LevelResponse{
					Message:     "level is required",
					ValidLevels: ValidLevelStrings(),
				}
				if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}

			// Parse and set level
			newLevel, err := ParseLevel(req.Level)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				resp := LevelResponse{
					Message:     err.Error(),
					ValidLevels: ValidLevelStrings(),
				}
				if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}

			previousLevel := logger.GetLevel().String()
			logger.SetLevel(newLevel)

			resp := LevelResponse{
				Level:         newLevel.String(),
				PreviousLevel: previousLevel,
				Message:       "log level updated successfully",
			}
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})
}

// LevelHandlerFunc is a convenience function that returns an http.HandlerFunc.
func LevelHandlerFunc(cfg LevelHandlerConfig) http.HandlerFunc {
	return LevelHandler(cfg).ServeHTTP
}

// LevelHandlerFiber returns a Fiber handler for managing log levels.
// GET: Returns the current log level.
// PUT/POST: Sets a new log level.
func LevelHandlerFiber(cfg LevelHandlerConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check authentication
		if cfg.RequireAuth && cfg.AuthFuncFiber != nil {
			if !cfg.AuthFuncFiber(c) {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Unauthorized",
				})
			}
		}

		// Check allowed IPs
		if len(cfg.AllowedIPs) > 0 {
			clientIP := c.IP()
			allowed := false
			for _, ip := range cfg.AllowedIPs {
				if ip == clientIP {
					allowed = true
					break
				}
			}
			if !allowed {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Forbidden",
				})
			}
		}

		logger := cfg.Logger
		if logger == nil {
			logger = defaultLogger
		}

		switch c.Method() {
		case fiber.MethodGet:
			// Return current level
			return c.JSON(LevelResponse{
				Level:       logger.GetLevel().String(),
				ValidLevels: ValidLevelStrings(),
			})

		case fiber.MethodPut, fiber.MethodPost:
			// Parse request
			var req LevelRequest
			if err := c.BodyParser(&req); err != nil {
				// Try query parameter
				req.Level = c.Query("level")
			}

			if req.Level == "" {
				return c.Status(fiber.StatusBadRequest).JSON(LevelResponse{
					Message:     "level is required",
					ValidLevels: ValidLevelStrings(),
				})
			}

			// Parse and set level
			newLevel, err := ParseLevel(req.Level)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(LevelResponse{
					Message:     err.Error(),
					ValidLevels: ValidLevelStrings(),
				})
			}

			previousLevel := logger.GetLevel().String()
			logger.SetLevel(newLevel)

			return c.JSON(LevelResponse{
				Level:         newLevel.String(),
				PreviousLevel: previousLevel,
				Message:       "log level updated successfully",
			})

		default:
			return c.Status(fiber.StatusMethodNotAllowed).JSON(fiber.Map{
				"error": "Method Not Allowed",
			})
		}
	}
}

// getClientIPStd extracts client IP from standard http.Request.
func getClientIPStd(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// RegisterLevelEndpoint registers the log level endpoint on a standard ServeMux.
func RegisterLevelEndpoint(mux *http.ServeMux, path string, cfg LevelHandlerConfig) {
	mux.Handle(path, LevelHandler(cfg))
}

// RegisterLevelEndpointFiber registers the log level endpoint on a Fiber app.
func RegisterLevelEndpointFiber(app *fiber.App, path string, cfg LevelHandlerConfig) {
	handler := LevelHandlerFiber(cfg)
	app.Get(path, handler)
	app.Put(path, handler)
	app.Post(path, handler)
}
