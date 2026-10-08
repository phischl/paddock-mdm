// Package cfg resolves the configuration of paddockctl (plan M6c decision 25): flags over environment over the
// config file. The token itself is never in the config file, only the path of the file that holds it.
package cfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/oasdiff/yaml"
)

// Config is the resolved configuration.
type Config struct {
	URL       string
	TokenFile string
	CAFile    string
}

// Sources are the values given on the command line and the environment lookup.
type Sources struct {
	URL, TokenFile, CAFile, ConfigFile string // flags; "" = not given
	Getenv                             func(string) string
}

// file is the config file.
type file struct {
	URL       string `json:"url"`
	TokenFile string `json:"token_file"`
	CAFile    string `json:"ca_file"`
}

// Error is a configuration error (exit code 2).
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

// Errorf returns a configuration error.
func Errorf(format string, a ...any) error { return &Error{msg: fmt.Sprintf(format, a...)} }

// Resolve combines flags, environment and config file. A missing default config file is not an error; a missing
// file named by --config is.
func Resolve(s Sources) (Config, error) {
	path, explicit := s.ConfigFile, s.ConfigFile != ""
	if !explicit {
		path = defaultPath(s.Getenv)
	}
	var f file
	if path != "" {
		raw, err := os.ReadFile(path) //nolint:gosec // the operator's own config file
		switch {
		case errors.Is(err, fs.ErrNotExist) && !explicit:
		case err != nil:
			return Config{}, Errorf("config file %s: %v", path, err)
		default:
			if _, err := yaml.Unmarshal(raw, &f, yaml.DecodeOpts{}, disallowUnknown); err != nil {
				return Config{}, Errorf("config file %s: %v", path, err)
			}
		}
	}
	c := Config{
		URL:       first(s.URL, s.Getenv("PADDOCK_URL"), f.URL),
		TokenFile: first(s.TokenFile, s.Getenv("PADDOCK_TOKEN_FILE"), f.TokenFile),
		CAFile:    first(s.CAFile, s.Getenv("PADDOCK_CA_FILE"), f.CAFile),
	}
	switch {
	case c.URL == "":
		return Config{}, Errorf("no admin API URL: set --url, PADDOCK_URL or url in %s", path)
	case !strings.HasPrefix(c.URL, "https://") && !strings.HasPrefix(c.URL, "http://"):
		return Config{}, Errorf("the URL %q must start with https://", c.URL)
	case c.TokenFile == "":
		return Config{}, Errorf("no token file: set --token-file, PADDOCK_TOKEN_FILE or token_file in %s", path)
	}
	c.URL = strings.TrimRight(c.URL, "/")
	return c, nil
}

func disallowUnknown(d *json.Decoder) *json.Decoder { d.DisallowUnknownFields(); return d }

func defaultPath(getenv func(string) string) string {
	if dir := getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "paddockctl", "config.yaml")
	}
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "paddockctl", "config.yaml")
	}
	return ""
}

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ReadToken reads the secret from the token file. The file must not be readable by group or others; trailing
// whitespace is trimmed.
func ReadToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", Errorf("token file: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", Errorf("token file %s is readable by others (mode %04o); chmod 600 it", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's own token file
	if err != nil {
		return "", Errorf("token file: %v", err)
	}
	secret := strings.TrimRight(string(raw), " \t\r\n")
	if secret == "" {
		return "", Errorf("token file %s is empty", path)
	}
	return secret, nil
}
