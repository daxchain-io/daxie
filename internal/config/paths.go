package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
)

// FlagValues are the global path/network flags the cli frontend binds and hands
// in. These path-ish vars are resolved OUTSIDE Viper (§7.3) — they are never
// config keys, so they never appear in config.toml and `config get` never lists
// them. (There is no --cache-dir flag; cache is env-only via DAXIE_CACHE_DIR.)
type FlagValues struct {
	Config   string // --config (file or dir)
	Keystore string // --keystore
	StateDir string // --state-dir
	Network  string // --network (default-network override; inert wrt I/O in M0)
}

// Paths are the four resolved state-class roots plus the derived config-file
// path and the registry dir (§7.2/§7.3). ConfigDir is ConfigFile's parent so the
// policy anchor is found beside the config.
type Paths struct {
	ConfigDir   string // the config directory
	ConfigFile  string // <ConfigDir>/config.toml (or the explicit --config file)
	Keystore    string // keystore root
	State       string // state root
	Cache       string // cache root
	RegistryDir string // DAXIE_REGISTRY_DIR override, else <State>/registry
}

// configFileName is the canonical config file basename.
const configFileName = "config.toml"

// lookupEnv is indirected so tests can inject an environment without touching
// the process env. Production points it at os.LookupEnv.
var lookupEnv = os.LookupEnv

// ResolvePaths applies the per-class override precedence — flag > DAXIE_* env >
// platform default (§7.3) — and derives ConfigFile/ConfigDir from the config
// override (which may name a file OR a directory). It creates nothing on disk;
// it only reads the environment via lookupEnv. A relative path resolved against
// $HOME failure (no HOME and no override) yields a domain.Error.
func ResolvePaths(f FlagValues) (Paths, error) {
	var p Paths

	// ── config (flag > DAXIE_CONFIG > platform default) ──
	cfgOverride := firstNonEmpty(f.Config, envOr("DAXIE_CONFIG"))
	if cfgOverride != "" {
		dir, file := splitConfigOverride(cfgOverride)
		p.ConfigDir = dir
		p.ConfigFile = file
	} else {
		dir, err := defaultConfigDir()
		if err != nil {
			return Paths{}, err
		}
		p.ConfigDir = dir
		p.ConfigFile = filepath.Join(dir, configFileName)
	}

	// ── keystore (flag > DAXIE_KEYSTORE > default) ──
	if ks := firstNonEmpty(f.Keystore, envOr("DAXIE_KEYSTORE")); ks != "" {
		p.Keystore = ks
	} else {
		d, err := defaultKeystoreDir()
		if err != nil {
			return Paths{}, err
		}
		p.Keystore = d
	}

	// ── state (flag > DAXIE_STATE_DIR > default) ──
	if st := firstNonEmpty(f.StateDir, envOr("DAXIE_STATE_DIR")); st != "" {
		p.State = st
	} else {
		d, err := defaultStateDir()
		if err != nil {
			return Paths{}, err
		}
		p.State = d
	}

	// ── cache (DAXIE_CACHE_DIR env only > default; no flag) ──
	if c := envOr("DAXIE_CACHE_DIR"); c != "" {
		p.Cache = c
	} else {
		d, err := defaultCacheDir()
		if err != nil {
			return Paths{}, err
		}
		p.Cache = d
	}

	// ── registry (DAXIE_REGISTRY_DIR env only > <State>/registry) ──
	if r := envOr("DAXIE_REGISTRY_DIR"); r != "" {
		p.RegistryDir = r
	} else {
		p.RegistryDir = filepath.Join(p.State, "registry")
	}

	return p, nil
}

// splitConfigOverride implements the §7.3 file-or-dir rule: a path ending in
// ".toml" is the config FILE (its parent is the dir); any other path is the dir
// (and the file is <dir>/config.toml). The K8s ConfigMap mount is a directory; a
// developer's `--config ./my.toml` is a file.
func splitConfigOverride(path string) (dir, file string) {
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		return filepath.Dir(path), path
	}
	return path, filepath.Join(path, configFileName)
}

// envOr returns the env value (trimmed of nothing — paths may legitimately
// contain spaces) or "" if unset.
func envOr(key string) string {
	v, ok := lookupEnv(key)
	if !ok {
		return ""
	}
	return v
}

// firstNonEmpty returns the first non-empty argument.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// homeDir resolves the user's home directory honoring $HOME first (so tests and
// containers can set it deterministically), then os.UserHomeDir. A failure is a
// usage-class config error rather than an opaque panic.
func homeDir() (string, error) {
	if h := envOr("HOME"); h != "" {
		return h, nil
	}
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return "", domain.New(domain.CodeConfigInvalid,
			"cannot determine home directory; set HOME or pass --config/--keystore/--state-dir")
	}
	return h, nil
}
