package logger

import (
	"encoding/json"
	"net"
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

	// TrustedProxies is a list of proxy IPs (or CIDRs). When non-empty, X-Forwarded-For
	// and X-Real-IP are only used when the direct peer (RemoteAddr) is in this list;
	// otherwise the client IP is taken from RemoteAddr only. When empty (default),
	// proxy headers are never trusted, preventing IP spoofing.
	// When behind a reverse proxy, set this to your proxy IPs so AllowedIPs works correctly.
	TrustedProxies []string

	// RequireAuth enables authentication check.
	// If true, requests must pass the AuthFunc check.
	RequireAuth bool

	// AuthFunc is a custom authentication function.
	// Returns true if the request is authenticated.
	AuthFunc func(r *http.Request) bool

	// AuthFuncFiber is a custom authentication function for Fiber.
	// Returns true if the request is authenticated.
	AuthFuncFiber func(c *fiber.Ctx) bool

	// MaxBodyBytes limits the request body size for PUT/POST (default 4096).
	// Requests larger than this return 413 Request Entity Too Large.
	MaxBodyBytes int64
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

// DefaultLevelMaxBodyBytes is the maximum request body size for level PUT/POST (4KB).
const DefaultLevelMaxBodyBytes = 4096

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
			clientIP := getClientIPStd(r, cfg.TrustedProxies)
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
			maxBody := cfg.MaxBodyBytes
			if maxBody <= 0 {
				maxBody = DefaultLevelMaxBodyBytes
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)

			var req LevelRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				if isRequestBodyTooLarge(err) {
					http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
					return
				}
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
			clientIP := getClientIPFiber(c, cfg.TrustedProxies)
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
			maxBody := cfg.MaxBodyBytes
			if maxBody <= 0 {
				maxBody = DefaultLevelMaxBodyBytes
			}
			body := c.Body()
			if len(body) > int(maxBody) {
				return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
					"error": "Request Entity Too Large",
				})
			}

			var req LevelRequest
			if len(body) > 0 {
				_ = json.Unmarshal(body, &req)
			}
			if req.Level == "" {
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

// remoteIPFromAddr extracts the IP from "host:port" or "[host]:port" (IPv6).
func remoteIPFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	// IPv6: "[::1]:1234" -> "::1"
	if len(addr) >= 2 && addr[0] == '[' {
		if end := strings.Index(addr, "]"); end != -1 {
			return addr[1:end]
		}
	}
	// IPv4: "192.168.1.1:1234" -> "192.168.1.1"
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// isIPInTrustedList returns true if ip is in the trusted list (exact match or CIDR).
func isIPInTrustedList(ipStr string, list []string) bool {
	if len(list) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, s := range list {
		s = strings.TrimSpace(s)
		if strings.Contains(s, "/") {
			_, network, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return true
			}
		} else {
			if net.ParseIP(s).Equal(ip) {
				return true
			}
		}
	}
	return false
}

// isRequestBodyTooLarge reports whether the error is from http.MaxBytesReader.
func isRequestBodyTooLarge(err error) bool {
	return err != nil && strings.Contains(err.Error(), "request body too large")
}

// getClientIPStd extracts client IP from standard http.Request.
// When trustedProxies is nil or empty, proxy headers (X-Forwarded-For, X-Real-IP) are
// not trusted and only RemoteAddr is used. When trustedProxies is set, proxy headers
// are only used when the direct peer (RemoteAddr) is in the trusted list.
func getClientIPStd(r *http.Request, trustedProxies []string) string {
	directIP := remoteIPFromAddr(r.RemoteAddr)
	if len(trustedProxies) == 0 || !isIPInTrustedList(directIP, trustedProxies) {
		return directIP
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return directIP
}

// getClientIPFiber extracts client IP from Fiber context with the same trusted-proxy
// semantics as getClientIPStd. When trustedProxies is empty, only the direct peer is used.
func getClientIPFiber(c *fiber.Ctx, trustedProxies []string) string {
	addr := c.Context().RemoteAddr().String()
	directIP := remoteIPFromAddr(addr)
	if len(trustedProxies) == 0 || !isIPInTrustedList(directIP, trustedProxies) {
		return directIP
	}
	if xff := c.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := c.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return directIP
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
