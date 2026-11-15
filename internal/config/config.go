// Package config validates the implemented runtime settings without side effects.
package config

import (
	"errors"
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// Config contains no credential material. Master-key loading remains in store.
type Config struct {
	LogLevel  slog.Level
	LogFormat string
	DataDir   string
	// PublicOrigin is the explicitly trusted HTTPS origin (scheme://host[:port]).
	// It is the ONLY source of the logged setup URL and of Host/Origin checks;
	// no request header is ever consulted. Empty means setup is unavailable.
	PublicOrigin string
	// Notice* configure the verified-TLS SMTP relay used for address
	// confirmation and security notices. All four are set together or none are.
	// No credential is read here (SMTP passwords live only in the encrypted store).
	NoticeRelay, NoticeTLS, NoticeSender, NoticeContact string
	// AdminListenAddr is the one HTTP listener (admin UI, /api/v1, /mcp). TLS is terminated by the
	// reverse proxy in front of it (TD §2.2); the process never serves plain HTTP on a public name.
	AdminListenAddr string
	// DockerSocket is the unix-socket path of the local endpoint. Empty (and not MockDocker) means no
	// Docker backend is composed: nothing in the process can reach a daemon.
	DockerSocket string
	// MockDocker selects the in-memory backend. It never coexists with DockerSocket.
	MockDocker bool
	// SelfContainerID and SelfInstanceUUID are the trusted operator's identity assertions (S1.1). They
	// are inputs to verification, never proof; the Docker adapter validates their exact format.
	SelfContainerID, SelfInstanceUUID string
}

func (Config) String() string       { return "[REDACTED]" }
func (Config) GoString() string     { return "[REDACTED]" }
func (Config) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// validPublicOrigin accepts only scheme://host[:port] over https: no userinfo,
// path, query or fragment, no whitespace/control characters. Validation never
// echoes the value.
func validPublicOrigin(origin string) bool {
	if len(origin) > 255 || strings.IndexFunc(origin, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !strings.HasSuffix(origin, "/") && u.Opaque == ""
}

// Load uses strict spellings: an invalid value is never echoed in diagnostics.
// An empty environment value selects the documented default.
func Load(getenv func(string) string) (Config, error) {
	c := Config{LogLevel: slog.LevelInfo, LogFormat: "json", DataDir: "/data"}
	switch getenv("MANDATARY_LOG_LEVEL") {
	case "", "info":
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "warn":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		return Config{}, errors.New("invalid MANDATARY_LOG_LEVEL")
	}
	switch getenv("MANDATARY_LOG_FORMAT") {
	case "", "json":
	case "text":
		c.LogFormat = "text"
	default:
		return Config{}, errors.New("invalid MANDATARY_LOG_FORMAT")
	}
	if path := getenv("MANDATARY_DATA_DIR"); path != "" {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return Config{}, errors.New("invalid MANDATARY_DATA_DIR")
		}
		c.DataDir = path
	}
	if origin := getenv("MANDATARY_PUBLIC_ORIGIN"); origin != "" {
		if !validPublicOrigin(origin) {
			return Config{}, errors.New("invalid MANDATARY_PUBLIC_ORIGIN")
		}
		c.PublicOrigin = origin
	}
	c.NoticeRelay, c.NoticeTLS = getenv("MANDATARY_SMTP_RELAY"), getenv("MANDATARY_SMTP_TLS")
	c.NoticeSender, c.NoticeContact = getenv("MANDATARY_SMTP_SENDER"), getenv("MANDATARY_NOTICE_CONTACT")
	set := 0
	for _, v := range []string{c.NoticeRelay, c.NoticeTLS, c.NoticeSender, c.NoticeContact} {
		if v != "" {
			set++
		}
	}
	if set != 0 && (set != 4 || c.PublicOrigin == "" || (c.NoticeTLS != "implicit" && c.NoticeTLS != "starttls")) {
		return Config{}, errors.New("invalid notice delivery settings")
	}
	for _, v := range []string{c.NoticeRelay, c.NoticeSender, c.NoticeContact} {
		if strings.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
			return Config{}, errors.New("invalid notice delivery settings")
		}
	}
	c.AdminListenAddr = DefaultAdminListenAddr
	if addr := getenv("MANDATARY_ADMIN_LISTEN_ADDR"); addr != "" {
		if !validListenAddr(addr) {
			return Config{}, errors.New("invalid MANDATARY_ADMIN_LISTEN_ADDR")
		}
		c.AdminListenAddr = addr
	}
	if socket := getenv("MANDATARY_DOCKER_SOCKET"); socket != "" {
		path, ok := unixSocketPath(socket)
		if !ok {
			return Config{}, errors.New("invalid MANDATARY_DOCKER_SOCKET")
		}
		c.DockerSocket = path
	}
	switch getenv("MANDATARY_DEV_MOCK_DOCKER") {
	case "", "false":
	case "true":
		c.MockDocker = true
	default:
		return Config{}, errors.New("invalid MANDATARY_DEV_MOCK_DOCKER")
	}
	if c.MockDocker && c.DockerSocket != "" {
		return Config{}, errors.New("invalid Docker backend settings")
	}
	c.SelfContainerID, c.SelfInstanceUUID = getenv("MANDATARY_SELF_CONTAINER_ID"), getenv("MANDATARY_SELF_INSTANCE_UUID")
	for _, v := range []string{c.SelfContainerID, c.SelfInstanceUUID} {
		if len(v) > 64 || strings.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
			return Config{}, errors.New("invalid self-identity settings")
		}
	}
	// TD 10.1: the operations listener is Phase 4. The documented default is the only
	// accepted spelling; no switch can open a second listener in this release.
	if v := getenv("MANDATARY_OPS_UI_ENABLED"); v != "" && v != "false" {
		return Config{}, errors.New("runtime setting not available in this release")
	}
	// These settings may not masquerade as implemented security/product controls.
	for _, name := range []string{"MANDATARY_OPS_LISTEN_ADDR", "MANDATARY_PASSWORD_HIBP_ENABLED"} {
		if getenv(name) != "" {
			return Config{}, errors.New("runtime setting not available in this release")
		}
	}
	return c, nil
}

// DefaultAdminListenAddr keeps an unconfigured process loopback-only. TD §13 names ":8080" as the
// packaged default; the image and the Compose example set it explicitly instead, so a process started
// without a deployment (make dev, a test) never exposes plain HTTP beyond the host.
const DefaultAdminListenAddr = "127.0.0.1:8080"

// validListenAddr accepts only "[IP]:port" with an empty or literal-IP host (no DNS lookup at bind
// time) and a decimal port in 1..65535.
func validListenAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" || len(port) > 5 || strings.IndexFunc(port, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return false
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return false
	}
	if host != "" {
		ip := net.ParseIP(host)
		if ip == nil || strings.Contains(host, "%") {
			return false
		}
	}
	return !strings.ContainsAny(addr, " 	\r\n/")
}

// unixSocketPath accepts only unix:///absolute/clean/path. Remote Docker transports are Phase 5.
func unixSocketPath(v string) (string, bool) {
	path, ok := strings.CutPrefix(v, "unix://")
	if !ok || len(path) > 255 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return "", false
	}
	return path, true
}
