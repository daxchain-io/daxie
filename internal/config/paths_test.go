package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// managedEnvVars is every environment variable this package reads. Tests clear
// all of them (so a developer's ambient DAXIE_*/XDG_* cannot leak into a test)
// then apply the desired overrides. We must use the REAL process env (t.Setenv)
// rather than injecting lookupEnv, because Viper's AutomaticEnv reads the OS
// environment directly — lookupEnv and Viper must agree.
var managedEnvVars = []string{
	"HOME",
	"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME",
	"APPDATA", "LOCALAPPDATA", "USERPROFILE",
	"DAXIE_CONFIG", "DAXIE_KEYSTORE", "DAXIE_STATE_DIR", "DAXIE_CACHE_DIR", "DAXIE_REGISTRY_DIR",
	"DAXIE_NETWORK", "DAXIE_SKIP_PERM_CHECK",
	"DAXIE_GAS_SPEED", "DAXIE_GAS_LIMIT_MULTIPLIER",
	"DAXIE_DEFAULTS_NETWORK", "DAXIE_TX_WAIT", "DAXIE_TX_WAIT_TIMEOUT",
	"ALCHEMY_API_KEY", "INFURA_PROJECT_ID", "NOPE", "FOO",
}

// withEnv clears every managed env var, then sets the provided overrides on the
// REAL process environment (so both lookupEnv and Viper observe them). An empty
// value clears the var (my path/ref logic treats "" as unset). lookupEnv is
// pinned to os.LookupEnv for the test.
func withEnv(t *testing.T, env map[string]string) {
	t.Helper()
	prev := lookupEnv
	lookupEnv = os.LookupEnv
	t.Cleanup(func() { lookupEnv = prev })
	for _, k := range managedEnvVars {
		if v, ok := env[k]; ok {
			t.Setenv(k, v)
		} else {
			t.Setenv(k, "")
		}
	}
	// Apply any override not in the managed list (e.g. a custom file path env).
	for k, v := range env {
		if !inManaged(k) {
			t.Setenv(k, v)
		}
	}
	// On Windows the default path resolution uses %USERPROFILE%/%APPDATA%/
	// %LOCALAPPDATA%, not $HOME. When a test sets only HOME (the POSIX base) and
	// does not pin the Windows bases, derive them from HOME so default-path tests
	// (which rely on the platform default rather than DAXIE_* / flags) stay
	// hermetic and pass on the Windows CI runners. No effect on POSIX resolution,
	// which reads HOME/XDG_*.
	if home := env["HOME"]; home != "" {
		if _, ok := env["USERPROFILE"]; !ok {
			t.Setenv("USERPROFILE", home)
		}
		if _, ok := env["APPDATA"]; !ok {
			t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
		}
		if _, ok := env["LOCALAPPDATA"]; !ok {
			t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
		}
	}
}

func inManaged(key string) bool {
	for _, k := range managedEnvVars {
		if k == key {
			return true
		}
	}
	return false
}

func TestResolvePathsFlagBeatsEnvBeatsDefault(t *testing.T) {
	withEnv(t, map[string]string{
		"HOME":            "/home/u",
		"DAXIE_CONFIG":    "/env/cfg",
		"DAXIE_KEYSTORE":  "/env/ks",
		"DAXIE_STATE_DIR": "/env/state",
	})
	// Flags override the env for the classes that have a flag.
	p, err := ResolvePaths(FlagValues{
		Config:   "/flag/cfg",
		Keystore: "/flag/ks",
		StateDir: "/flag/state",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.ConfigDir != "/flag/cfg" {
		t.Errorf("config dir = %q, want /flag/cfg (flag wins)", p.ConfigDir)
	}
	if p.Keystore != "/flag/ks" {
		t.Errorf("keystore = %q, want /flag/ks", p.Keystore)
	}
	if p.State != "/flag/state" {
		t.Errorf("state = %q, want /flag/state", p.State)
	}
}

func TestResolvePathsEnvBeatsDefault(t *testing.T) {
	withEnv(t, map[string]string{
		"HOME":               "/home/u",
		"DAXIE_CONFIG":       "/env/cfg",
		"DAXIE_KEYSTORE":     "/env/ks",
		"DAXIE_STATE_DIR":    "/env/state",
		"DAXIE_CACHE_DIR":    "/env/cache",
		"DAXIE_REGISTRY_DIR": "/env/reg",
	})
	p, err := ResolvePaths(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	if p.ConfigDir != "/env/cfg" || p.Keystore != "/env/ks" || p.State != "/env/state" ||
		p.Cache != "/env/cache" || p.RegistryDir != "/env/reg" {
		t.Errorf("env did not win: %+v", p)
	}
	// ConfigFile derives from a non-.toml dir override.
	if p.ConfigFile != filepath.Join("/env/cfg", "config.toml") {
		t.Errorf("config file = %q, want /env/cfg/config.toml", p.ConfigFile)
	}
}

func TestConfigOverrideFileOrDir(t *testing.T) {
	withEnv(t, map[string]string{"HOME": "/home/u"})
	// A .toml override is the FILE; its parent is the dir.
	p, err := ResolvePaths(FlagValues{Config: "/x/my.toml"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ConfigFile != "/x/my.toml" || p.ConfigDir != "/x" {
		t.Errorf("file override: got file=%q dir=%q, want /x/my.toml and /x", p.ConfigFile, p.ConfigDir)
	}
	// A non-.toml override is the DIR; the file is <dir>/config.toml.
	p2, err := ResolvePaths(FlagValues{Config: "/x/confdir"})
	if err != nil {
		t.Fatal(err)
	}
	if p2.ConfigDir != "/x/confdir" || p2.ConfigFile != filepath.Join("/x/confdir", "config.toml") {
		t.Errorf("dir override: got dir=%q file=%q", p2.ConfigDir, p2.ConfigFile)
	}
}

func TestRegistryDefaultsUnderState(t *testing.T) {
	withEnv(t, map[string]string{"HOME": "/home/u", "DAXIE_STATE_DIR": "/s"})
	p, err := ResolvePaths(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	if p.RegistryDir != filepath.Join("/s", "registry") {
		t.Errorf("registry = %q, want /s/registry", p.RegistryDir)
	}
}

// TestDefaultPathsPerPlatform exercises the platform default roots. On unix it
// checks the XDG-honoring and $HOME-fallback paths; on windows it checks the
// %APPDATA%/%LOCALAPPDATA% split.
func TestDefaultPathsPerPlatform(t *testing.T) {
	if runtime.GOOS == "windows" {
		withEnv(t, map[string]string{
			"APPDATA":      `C:\Users\u\AppData\Roaming`,
			"LOCALAPPDATA": `C:\Users\u\AppData\Local`,
		})
		p, err := ResolvePaths(FlagValues{})
		if err != nil {
			t.Fatal(err)
		}
		if p.ConfigDir != filepath.Join(`C:\Users\u\AppData\Roaming`, "daxie") {
			t.Errorf("windows config dir = %q", p.ConfigDir)
		}
		if p.Keystore != filepath.Join(`C:\Users\u\AppData\Local`, "daxie", "keystore") {
			t.Errorf("windows keystore = %q", p.Keystore)
		}
		return
	}

	// Unix: $HOME fallback (no XDG vars).
	withEnv(t, map[string]string{"HOME": "/home/u"})
	p, err := ResolvePaths(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	wantCfg := filepath.Join("/home/u", ".config", "daxie")
	wantKs := filepath.Join("/home/u", ".local", "share", "daxie", "keystore")
	wantState := filepath.Join("/home/u", ".local", "state", "daxie")
	wantCache := filepath.Join("/home/u", ".cache", "daxie")
	if p.ConfigDir != wantCfg || p.Keystore != wantKs || p.State != wantState || p.Cache != wantCache {
		t.Errorf("unix $HOME defaults wrong:\n got %+v\n want cfg=%s ks=%s state=%s cache=%s",
			p, wantCfg, wantKs, wantState, wantCache)
	}

	// Unix: XDG vars honored.
	withEnv(t, map[string]string{
		"HOME":            "/home/u",
		"XDG_CONFIG_HOME": "/xdg/config",
		"XDG_DATA_HOME":   "/xdg/data",
		"XDG_STATE_HOME":  "/xdg/state",
		"XDG_CACHE_HOME":  "/xdg/cache",
	})
	p2, err := ResolvePaths(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	if p2.ConfigDir != filepath.Join("/xdg/config", "daxie") {
		t.Errorf("XDG config = %q", p2.ConfigDir)
	}
	if p2.Keystore != filepath.Join("/xdg/data", "daxie", "keystore") {
		t.Errorf("XDG keystore = %q", p2.Keystore)
	}
	if p2.State != filepath.Join("/xdg/state", "daxie") {
		t.Errorf("XDG state = %q", p2.State)
	}
	if p2.Cache != filepath.Join("/xdg/cache", "daxie") {
		t.Errorf("XDG cache = %q", p2.Cache)
	}
}
