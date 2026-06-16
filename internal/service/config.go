package service

import (
	"context"

	"github.com/daxchain-io/daxie/internal/config"
)

// The config get/set/list use cases back `daxie config get|set|list`. Each is
// one method per use case (§2.4). The service is the single caller the frontends
// reach — the cli never touches internal/config directly (the arch matrix forbids
// frontend→config), so these thin methods are the sanctioned bridge AND the
// re-export point for the one config shape the frontend renders (ConfigEntry).
//
// config.* error codes (config.read_only exit 10, ref.not_found exit 10,
// usage.* exit 2 for a rejected policy.* key) originate in internal/config and
// flow back unchanged through the cli render registry.

// ConfigEntry is the service-owned re-export of one listed config key. It mirrors
// config.KV so the cli can render `config list` without importing the config
// provider (arch matrix: frontends import service+domain only). The json tags
// match the wire shape the --json output emits.
type ConfigEntry struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"` // "default" | "file" | "env" | "flag"
}

// ConfigList returns every operator-visible config key with its effective value
// and the source it came from (default|file|env|flag). The five path vars and
// the policy.* subtree are excluded by internal/config (§7.3, §7.6).
func (s *Service) ConfigList(ctx context.Context) []ConfigEntry {
	kvs := s.cfg.ListKeys()
	out := make([]ConfigEntry, len(kvs))
	for i, kv := range kvs {
		out[i] = ConfigEntry(kv)
	}
	return out
}

// ConfigGet returns one key's effective value, or ref.not_found (exit 10) for an
// unknown key.
func (s *Service) ConfigGet(ctx context.Context, key string) (string, error) {
	return s.cfg.GetKey(key)
}

// ConfigSet performs the §7.4 targeted raw-file rewrite of config.toml under the
// config.lock sidecar via fsx.WriteAtomic. It rejects any policy.* key (usage.*,
// exit 2) and maps a read-only mount to config.read_only (exit 10). The config
// dir is created here lazily if absent — the only M0 path that writes config.
func (s *Service) ConfigSet(ctx context.Context, key, value string) error {
	return config.SetKey(s.paths, key, value)
}
