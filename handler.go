package logger

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
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
		if cfg.RequireAuth && cfg.AuthFunc == nil {
			http.Error(w, "AuthFunc is required when RequireAuth is enabled", http.StatusInternalServerError)
			return
		}

		authenticated := !cfg.RequireAuth || cfg.AuthFunc(r)
		if denied := cfg.Authorize(RequestSource(r), authenticated); denied != nil {
			http.Error(w, denied.Error, denied.StatusCode)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		var outcome LevelOutcome
		switch r.Method {
		case http.MethodGet:
			outcome = cfg.CurrentLevel()

		case http.MethodPut, http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBody())

			var req LevelRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				if isRequestBodyTooLarge(err) {
					http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
					return
				}
				req.Level = r.URL.Query().Get("level")
			}
			outcome = cfg.ApplyLevel(req.Level)

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if outcome.StatusCode != http.StatusOK {
			w.WriteHeader(outcome.StatusCode)
		}
		if err := json.NewEncoder(w).Encode(outcome.Body); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})
}

// LevelHandlerFunc is a convenience function that returns an http.HandlerFunc.
func LevelHandlerFunc(cfg LevelHandlerConfig) http.HandlerFunc {
	return LevelHandler(cfg).ServeHTTP
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

// ClientIPSource is the minimal view of a request needed to resolve a client
// IP. Implementing it is all a framework adapter has to do -- see the
// fiberadapter subpackage.
type ClientIPSource interface {
	// RemoteAddr is the direct peer address, "host:port" or "[host]:port".
	RemoteAddr() string
	// Header returns a request header, or "" when absent.
	Header(name string) string
}

// ClientIP resolves the client IP under the trusted-proxy rule: X-Forwarded-For
// then X-Real-IP, but only when the direct peer is itself in trustedProxies.
// With an empty list the proxy headers are never trusted, which is what keeps
// AllowedIPs from being spoofable.
//
// Exported, and taking an interface, so the rule has exactly one
// implementation. It used to have two -- one per framework -- and a
// trusted-proxy rule that disagrees with itself across frameworks is an
// AllowedIPs bypass, not a cosmetic difference.
func ClientIP(src ClientIPSource, trustedProxies []string) string {
	directIP := remoteIPFromAddr(src.RemoteAddr())
	if len(trustedProxies) == 0 || !isIPInTrustedList(directIP, trustedProxies) {
		return directIP
	}
	if xff := src.Header("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := src.Header("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return directIP
}

// RequestSource adapts an *http.Request to ClientIPSource.
func RequestSource(r *http.Request) ClientIPSource { return stdSource{r: r} }

type stdSource struct{ r *http.Request }

func (s stdSource) RemoteAddr() string        { return s.r.RemoteAddr }
func (s stdSource) Header(name string) string { return s.r.Header.Get(name) }

// LevelOutcome is what the level endpoint should return, computed without
// reference to any web framework.
type LevelOutcome struct {
	// StatusCode is the HTTP status to send.
	StatusCode int

	// Body, when non-nil, is the LevelResponse to serialize as JSON.
	Body *LevelResponse

	// Error, when non-empty, is a plain message. Each adapter renders it the
	// way it always has -- LevelHandler as text/plain, the Fiber handler as
	// {"error": ...} -- and this change deliberately does not unify them.
	Error string
}

// Authorize applies the level endpoint's access checks: the caller's auth
// result (ignored when RequireAuth is false) and the AllowedIPs list. It
// returns nil when the request may proceed.
//
// The auth *function* stays with the caller: its signature is
// framework-specific, and so is the message for a missing one.
func (cfg LevelHandlerConfig) Authorize(src ClientIPSource, authenticated bool) *LevelOutcome {
	if cfg.RequireAuth && !authenticated {
		return &LevelOutcome{StatusCode: http.StatusUnauthorized, Error: "Unauthorized"}
	}

	if len(cfg.AllowedIPs) > 0 {
		clientIP := ClientIP(src, cfg.TrustedProxies)
		for _, ip := range cfg.AllowedIPs {
			if ip == clientIP {
				return nil
			}
		}
		return &LevelOutcome{StatusCode: http.StatusForbidden, Error: "Forbidden"}
	}

	return nil
}

// CurrentLevel is the GET response: the level in force and the valid names.
func (cfg LevelHandlerConfig) CurrentLevel() LevelOutcome {
	return LevelOutcome{
		StatusCode: http.StatusOK,
		Body: &LevelResponse{
			Level:       cfg.logger().GetLevel().String(),
			ValidLevels: ValidLevelStrings(),
		},
	}
}

// ApplyLevel is the PUT/POST response: it validates name, and on success sets
// the level and reports what it was before. An empty or unparseable name is a
// 400 carrying the valid names, not an error string.
func (cfg LevelHandlerConfig) ApplyLevel(name string) LevelOutcome {
	if name == "" {
		return LevelOutcome{
			StatusCode: http.StatusBadRequest,
			Body:       &LevelResponse{Message: "level is required", ValidLevels: ValidLevelStrings()},
		}
	}

	newLevel, err := ParseLevel(name)
	if err != nil {
		return LevelOutcome{
			StatusCode: http.StatusBadRequest,
			Body:       &LevelResponse{Message: err.Error(), ValidLevels: ValidLevelStrings()},
		}
	}

	logger := cfg.logger()
	previousLevel := logger.GetLevel().String()
	logger.SetLevel(newLevel)

	return LevelOutcome{
		StatusCode: http.StatusOK,
		Body: &LevelResponse{
			Level:         newLevel.String(),
			PreviousLevel: previousLevel,
			Message:       "log level updated successfully",
		},
	}
}

// MaxBody is the configured request-body limit for PUT/POST, or the default.
func (cfg LevelHandlerConfig) MaxBody() int64 {
	if cfg.MaxBodyBytes <= 0 {
		return DefaultLevelMaxBodyBytes
	}
	return cfg.MaxBodyBytes
}

func (cfg LevelHandlerConfig) logger() *Logger {
	if cfg.Logger == nil {
		return defaultLogger
	}
	return cfg.Logger
}

// RegisterLevelEndpoint registers the log level endpoint on a standard ServeMux.
func RegisterLevelEndpoint(mux *http.ServeMux, path string, cfg LevelHandlerConfig) {
	mux.Handle(path, LevelHandler(cfg))
}
