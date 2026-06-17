package config

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
	toml "github.com/pelletier/go-toml/v2"
)

// configMode is the permission for a freshly written config file (operator-
// owned, no secrets, but still owner-only by default per the §7.9 posture).
const configMode os.FileMode = 0o600

// SetKey performs the §7.4 raw-file targeted rewrite: it loads the existing
// config.toml into a map[string]any, applies the single change, and rewrites it
// under the config.lock sidecar via fsx.WriteAtomic. Values the operator never
// set stay absent (keep inheriting built-ins/env); unknown keys (the reserved
// [mcp] block, x- keys) survive.
//
// It rejects any policy.* key (usage.*, §7.6) and any unknown scalar key
// (ref.not_found). A read-only mount maps to config.read_only (exit 10) — never
// an opaque permission error (§7.10). The config dir is created lazily here, the
// one place an M0 command writes config (§7.3).
func SetKey(p Paths, key, value string) error {
	if isPolicyKey(key) {
		return domain.Newf(domain.CodeUsage+".policy_key",
			"%q is a policy key — set it with `daxie policy ...` (admin passphrase), not `config set`", key)
	}
	if _, ok := scalarKeySet[key]; !ok {
		return domain.Newf(domain.CodeRefNotFound, "unknown config key %q", key)
	}
	typed, err := coerceValue(key, value)
	if err != nil {
		return err
	}

	// Lazily create the config dir (the only M0 config write). A read-only
	// parent surfaces as config.read_only via the WriteAtomic mapping below; here
	// we map a mkdir failure too.
	if err := fsx.MkdirAll(p.ConfigDir, 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return readOnlyErr(p.ConfigFile, err)
		}
		return domain.Wrap(domain.CodeConfigInvalid,
			"creating config dir "+p.ConfigDir+": "+err.Error(), err)
	}

	// Serialize the read-modify-write under the config.lock sidecar (§7.9).
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	unlock, err := fsx.Lock(ctx, p.ConfigFile)
	if err != nil {
		return mapLockErr(p.ConfigFile, err)
	}
	defer unlock()

	raw, err := loadRawForWrite(p.ConfigFile)
	if err != nil {
		return err
	}
	if _, ok := raw["schema"]; !ok {
		raw["schema"] = int64(SchemaVersion)
	}
	setNested(raw, key, typed)

	data, err := toml.Marshal(raw)
	if err != nil {
		return domain.Wrap(domain.CodeConfigInvalid, "encoding config: "+err.Error(), err)
	}
	if err := fsx.WriteAtomic(p.ConfigFile, data, configMode); err != nil {
		if fsx.IsReadOnly(err) {
			return readOnlyErr(p.ConfigFile, err)
		}
		return domain.Wrap(domain.CodeConfigInvalid,
			"writing "+p.ConfigFile+": "+err.Error(), err)
	}
	return nil
}

// mutateRaw runs the §7.4 read-modify-write transaction for the object mutators
// (network/rpc add/use/rename/remove) under the config.lock sidecar: it lazily
// creates the config dir, takes the lock, loads the raw config into a map, calls
// apply to mutate it in place, then rewrites atomically. apply returns an error to
// ABORT the write (e.g. a not-found / read-only / duplicate check the mutator runs
// after seeing the current file state); the partial mutation is discarded because
// nothing is written. A read-only mount maps to config.read_only at every step
// (mkdir, load, write) — never an opaque permission error (§7.10).
//
// This is the same transaction SetKey performs; SetKey predates it and keeps its
// own inline body, but every M2 object mutator funnels through here so the
// lock/dir/read-only discipline lives in one place.
func mutateRaw(p Paths, apply func(raw map[string]any) error) error {
	if err := fsx.MkdirAll(p.ConfigDir, 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return readOnlyErr(p.ConfigFile, err)
		}
		return domain.Wrap(domain.CodeConfigInvalid,
			"creating config dir "+p.ConfigDir+": "+err.Error(), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	unlock, err := fsx.Lock(ctx, p.ConfigFile)
	if err != nil {
		return mapLockErr(p.ConfigFile, err)
	}
	defer unlock()

	raw, err := loadRawForWrite(p.ConfigFile)
	if err != nil {
		return err
	}
	if _, ok := raw["schema"]; !ok {
		raw["schema"] = int64(SchemaVersion)
	}
	if err := apply(raw); err != nil {
		return err
	}

	data, err := toml.Marshal(raw)
	if err != nil {
		return domain.Wrap(domain.CodeConfigInvalid, "encoding config: "+err.Error(), err)
	}
	if err := fsx.WriteAtomic(p.ConfigFile, data, configMode); err != nil {
		if fsx.IsReadOnly(err) {
			return readOnlyErr(p.ConfigFile, err)
		}
		return domain.Wrap(domain.CodeConfigInvalid,
			"writing "+p.ConfigFile+": "+err.Error(), err)
	}
	return nil
}

// rawSubTable returns the nested table at the dotted key, or nil if absent or not
// a table. It does not create intermediate tables (read-only lookup).
func rawSubTable(m map[string]any, parts ...string) map[string]any {
	cur := m
	for _, p := range parts {
		next, ok := cur[p].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// deleteNested removes a dotted key from a nested map, pruning a now-empty parent
// table it created no siblings in. It is the inverse of setNested.
func deleteNested(m map[string]any, key string) {
	parts := splitKey(key)
	if len(parts) == 1 {
		delete(m, parts[0])
		return
	}
	parent := rawSubTable(m, parts[:len(parts)-1]...)
	if parent == nil {
		return
	}
	delete(parent, parts[len(parts)-1])
	if len(parent) == 0 {
		// Prune the empty parent table so a removed [rpc.x] does not leave an empty
		// [rpc] block behind.
		deleteNested(m, joinKey(parts[:len(parts)-1]))
	}
}

// joinKey rejoins dotted segments.
func joinKey(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "."
		}
		out += p
	}
	return out
}

// loadRawForWrite reads the existing config into a map for rewrite, returning an
// empty map when the file does not yet exist (the fresh-write case).
func loadRawForWrite(file string) (map[string]any, error) {
	data, err := os.ReadFile(file) // #nosec G304 -- file is the resolved config.toml path (operator-controlled), read to preserve unknown keys on rewrite
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]any{}, nil
		}
		if fsx.IsReadOnly(err) {
			return nil, readOnlyErr(file, err)
		}
		return nil, domain.Wrap(domain.CodeConfigInvalid, "reading "+file+": "+err.Error(), err)
	}
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, domain.Wrap(domain.CodeConfigInvalid, "parsing "+file+": "+err.Error(), err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// setNested sets a dotted key into a nested map[string]any, creating intermediate
// tables as needed and preserving sibling keys.
func setNested(m map[string]any, key string, value any) {
	parts := splitKey(key)
	cur := m
	for i := 0; i < len(parts)-1; i++ {
		next, ok := cur[parts[i]].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[parts[i]] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value
}

// splitKey splits a dotted key into segments.
func splitKey(key string) []string {
	var out []string
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '.' {
			out = append(out, key[start:i])
			start = i + 1
		}
	}
	out = append(out, key[start:])
	return out
}

// coerceValue validates and converts a string value to the typed value the key
// expects, returning a usage.* error on a bad value (caught here, not at next
// load). Durations are stored as their canonical strings (TOML has no duration
// type); numbers as int64/float64; bools as bool.
func coerceValue(key, value string) (any, error) {
	switch keyType(key) {
	case typeString:
		return value, nil
	case typeBool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return nil, domain.Newf(domain.CodeUsage+".bad_value",
				"%q expects a boolean (true/false), got %q", key, value)
		}
		return b, nil
	case typeInt:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, domain.Newf(domain.CodeUsage+".bad_value",
				"%q expects an integer, got %q", key, value)
		}
		return n, nil
	case typeFloat:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, domain.Newf(domain.CodeUsage+".bad_value",
				"%q expects a number, got %q", key, value)
		}
		return f, nil
	case typeDuration:
		d, err := time.ParseDuration(value)
		if err != nil {
			return nil, domain.Newf(domain.CodeUsage+".bad_value",
				"%q expects a duration like \"5m\", got %q", key, value)
		}
		return d.String(), nil // store canonical string form
	case typeFee:
		// A fee floor like "0.01gwei": stored as a string, validated shallowly
		// (non-empty). Full unit parsing is core's job at use time.
		if value == "" {
			return nil, domain.Newf(domain.CodeUsage+".bad_value",
				"%q expects a fee like \"0.01gwei\"", key)
		}
		return value, nil
	default:
		return value, nil
	}
}

// readOnlyErr builds the canonical config.read_only error naming the file and the
// remedy (§7.10).
func readOnlyErr(file string, cause error) error {
	return domain.WithData(
		domain.Wrap(domain.CodeConfigReadOnly,
			"config file "+file+" is on a read-only mount; set the value in the ConfigMap, "+
				"pass the flag per call, or use the DAXIE_* env override", cause),
		map[string]any{"file": file},
	)
}

// mapLockErr maps a lock-acquisition failure to state.lock_timeout (a contended
// or stuck lock) unless the lock dir itself is read-only.
func mapLockErr(file string, cause error) error {
	if fsx.IsReadOnly(cause) {
		return readOnlyErr(file, cause)
	}
	return domain.WithData(
		domain.Wrap(domain.CodeStateLockTimeout,
			"could not acquire the config lock for "+file+": "+cause.Error(), cause),
		map[string]any{"file": file},
	)
}
