//go:build !windows

package config

import "path/filepath"

// Linux & macOS path defaults (§7.3). macOS deliberately MIRRORS Linux XDG —
// the audience is terminal-first, so we do not use ~/Library or
// os.UserConfigDir/UserCacheDir (which return ~/Library/… on macOS). Each class
// honors its XDG_* env when set, otherwise an explicit $HOME join.

// defaultConfigDir: $XDG_CONFIG_HOME/daxie -> ~/.config/daxie.
func defaultConfigDir() (string, error) {
	return xdgJoin("XDG_CONFIG_HOME", ".config", "daxie")
}

// defaultKeystoreDir: $XDG_DATA_HOME/daxie/keystore -> ~/.local/share/daxie/keystore.
func defaultKeystoreDir() (string, error) {
	return xdgJoin("XDG_DATA_HOME", filepath.Join(".local", "share"), "daxie", "keystore")
}

// defaultStateDir: $XDG_STATE_HOME/daxie -> ~/.local/state/daxie. State uses the
// XDG state class (not data) so a tar of the keystore dir is a pure key backup.
func defaultStateDir() (string, error) {
	return xdgJoin("XDG_STATE_HOME", filepath.Join(".local", "state"), "daxie")
}

// defaultCacheDir: $XDG_CACHE_HOME/daxie -> ~/.cache/daxie.
func defaultCacheDir() (string, error) {
	return xdgJoin("XDG_CACHE_HOME", ".cache", "daxie")
}

// xdgJoin returns <$xdgVar>/<sub…> when the XDG var is set, otherwise
// <home>/<homeBase>/<sub…>. homeBase is the directory under $HOME that the XDG
// var would default to (e.g. ".config").
func xdgJoin(xdgVar, homeBase string, sub ...string) (string, error) {
	if root := envOr(xdgVar); root != "" {
		return filepath.Join(append([]string{root}, sub...)...), nil
	}
	home, err := homeDir()
	if err != nil {
		return "", err
	}
	parts := append([]string{home, homeBase}, sub...)
	return filepath.Join(parts...), nil
}
