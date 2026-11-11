// Package config validates the implemented runtime settings without side effects.
package config

import (
	"errors"
	"log/slog"
	"net/url"
	"path/filepath"
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
	// These settings may not masquerade as implemented security/product controls.
	for _, name := range []string{"MANDATARY_ADMIN_LISTEN_ADDR", "MANDATARY_DOCKER_SOCKET", "MANDATARY_DEV_MOCK_DOCKER", "MANDATARY_OPS_UI_ENABLED", "MANDATARY_OPS_LISTEN_ADDR", "MANDATARY_PASSWORD_HIBP_ENABLED"} {
		if getenv(name) != "" {
			return Config{}, errors.New("runtime setting not available in the development skeleton")
		}
	}
	return c, nil
}
