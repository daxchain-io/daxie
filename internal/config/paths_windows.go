//go:build windows

package config

import (
	"path/filepath"

	"github.com/daxchain-io/daxie/internal/domain"
)

// Windows path defaults (§7.3). CONFIG ROAMS, KEYS DO NOT: config lives under the
// roaming %APPDATA% (it holds no secret — RPC keys are ${env:}/${file:}
// references), while keystore/state/cache live under the non-roaming
// %LOCALAPPDATA% so key material is never replicated across domain machines by
// roaming profiles.

// defaultConfigDir: %APPDATA%\daxie.
func defaultConfigDir() (string, error) {
	root, err := appData()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "daxie"), nil
}

// defaultKeystoreDir: %LOCALAPPDATA%\daxie\keystore.
func defaultKeystoreDir() (string, error) {
	root, err := localAppData()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "daxie", "keystore"), nil
}

// defaultStateDir: %LOCALAPPDATA%\daxie\state.
func defaultStateDir() (string, error) {
	root, err := localAppData()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "daxie", "state"), nil
}

// defaultCacheDir: %LOCALAPPDATA%\daxie\cache.
func defaultCacheDir() (string, error) {
	root, err := localAppData()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "daxie", "cache"), nil
}

// appData reads %APPDATA% (roaming), falling back to %USERPROFILE%\AppData\Roaming.
func appData() (string, error) {
	if v := envOr("APPDATA"); v != "" {
		return v, nil
	}
	if up := envOr("USERPROFILE"); up != "" {
		return filepath.Join(up, "AppData", "Roaming"), nil
	}
	return "", domain.New(domain.CodeConfigInvalid,
		"cannot determine %APPDATA%; set APPDATA/USERPROFILE or pass --config")
}

// localAppData reads %LOCALAPPDATA% (non-roaming), falling back to
// %USERPROFILE%\AppData\Local.
func localAppData() (string, error) {
	if v := envOr("LOCALAPPDATA"); v != "" {
		return v, nil
	}
	if up := envOr("USERPROFILE"); up != "" {
		return filepath.Join(up, "AppData", "Local"), nil
	}
	return "", domain.New(domain.CodeConfigInvalid,
		"cannot determine %LOCALAPPDATA%; set LOCALAPPDATA/USERPROFILE or pass --keystore/--state-dir")
}
