package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
	toml "github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"
)

// envPrefix is the DAXIE_* env namespace; the replacer maps both '.' and '-' to
// '_' so gas.limit-multiplier -> DAXIE_GAS_LIMIT_MULTIPLIER (§7.1).
const envPrefix = "DAXIE"

// Load resolves the four roots, reads config.toml + env + flags, and unmarshals
// to one immutable *Config (§7.4). Precedence is built-in defaults < file < env
// < flags. It NEVER resolves secret references (§7.5). The policy.* subtree is
// excluded from the unmarshal (§4.6).
//
// A --config naming a missing FILE is config.not_found; an absent DEFAULT file
// is the legitimate fresh-install case (Load returns the built-in defaults). A
// newer file schema major is config.schema_unsupported; a bad value type is
// config.invalid (caught once, here).
func Load(f FlagValues) (*Config, Paths, error) {
	paths, err := ResolvePaths(f)
	if err != nil {
		return nil, Paths{}, err
	}

	// Read the raw file (if present) once: used for existence/schema checks and
	// the sparse networks/rpc merge. go-toml is the backend (§7.1).
	raw, present, err := readRawConfig(f, paths)
	if err != nil {
		return nil, Paths{}, err
	}
	if present {
		if err := checkSchema(raw, paths.ConfigFile); err != nil {
			return nil, Paths{}, err
		}
	}

	// Scalar precedence (defaults < file < env) via Viper. Defaults are
	// registered so env values (AutomaticEnv) participate in Unmarshal — Viper
	// only surfaces an env-only key through Unmarshal if the key is known. Viper
	// owns env mapping + precedence and lives ONLY in this package (§2.2).
	v := newViper()
	registerDefaults(v)
	if err := applyFile(v, raw, present); err != nil {
		return nil, Paths{}, err
	}
	var cfg Config
	if err := v.Unmarshal(&cfg, viper.DecodeHook(stringConvertHook)); err != nil {
		return nil, Paths{}, domain.Wrap(domain.CodeConfigInvalid,
			"config "+paths.ConfigFile+": "+err.Error(), err)
	}

	// Networks/RPC are NOT unmarshaled by Viper (they are excluded from the
	// merge): seed the built-in tables, then overlay the file's [networks.*]/
	// [rpc.*] field-by-field so the sparse-override + geth value-type semantics
	// are exact.
	cfg.Networks = builtinNetworks()
	cfg.RPC = builtinRPC()
	if err := mergeNetworksAndRPC(&cfg, raw); err != nil {
		return nil, Paths{}, err
	}
	if cfg.MCP == nil {
		cfg.MCP = map[string]any{}
	}

	// --network flag is the highest-precedence override of the default network
	// selection. Inert wrt I/O in M0 but wired here (§0 inert-but-honest).
	if f.Network != "" {
		cfg.Defaults.Network = f.Network
	}

	cfg.Schema = SchemaVersion
	cfg.sources = computeSources(raw, f)
	return &cfg, paths, nil
}

// computeSources attributes each operator-visible scalar key to its winning
// layer for `config list` (§7.3). Precedence flag > env > file > default. Only
// the keys ListKeys enumerates are attributed.
func computeSources(raw map[string]any, f FlagValues) map[string]string {
	src := make(map[string]string, len(scalarKeys))
	for _, k := range scalarKeys {
		switch {
		case k == "defaults.network" && f.Network != "":
			src[k] = "flag"
		case envSetFor(k):
			src[k] = "env"
		case rawHasKey(raw, k):
			src[k] = "file"
		default:
			src[k] = "default"
		}
	}
	return src
}

// envSetFor reports whether the DAXIE_* env var backing a dotted key is set to a
// NON-EMPTY value (mirrors the §7.1 replacer '.'/'-' -> '_', upper-cased, DAXIE_
// prefix, and Viper's default AllowEmptyEnv(false) — an empty env var does not
// override, so it is not attributed as the source).
func envSetFor(key string) bool {
	env := envPrefix + "_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(key))
	v, ok := lookupEnv(env)
	return ok && v != ""
}

// rawHasKey reports whether the raw file map set a dotted scalar key (walking
// nested tables).
func rawHasKey(raw map[string]any, key string) bool {
	if raw == nil {
		return false
	}
	parts := strings.Split(key, ".")
	cur := raw
	for i, p := range parts {
		v, ok := cur[p]
		if !ok {
			return false
		}
		if i == len(parts)-1 {
			return true
		}
		next, ok := v.(map[string]any)
		if !ok {
			return false
		}
		cur = next
	}
	return false
}

// readRawConfig loads the config file into a map[string]any. It distinguishes a
// named-but-missing --config file (config.not_found) from an absent default file
// (fresh install: present=false, no error).
func readRawConfig(f FlagValues, paths Paths) (map[string]any, bool, error) {
	data, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// config.not_found ONLY when the operator explicitly named a .toml
			// FILE that is missing. A directory override (K8s ConfigMap mount) or
			// the platform default with no config.toml yet is the legitimate
			// fresh-install case — `config list`/`convert`/`version` must still
			// run (§7.3 lazy Open).
			if userNamedConfigFile(f) {
				return nil, false, domain.Newf(domain.CodeConfigNotFound,
					"config file %s does not exist", paths.ConfigFile)
			}
			return nil, false, nil
		}
		return nil, false, domain.Wrap(domain.CodeConfigInvalid,
			"reading "+paths.ConfigFile+": "+err.Error(), err)
	}
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, false, domain.Wrap(domain.CodeConfigInvalid,
			"parsing "+paths.ConfigFile+": "+err.Error(), err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, true, nil
}

// userNamedConfigFile reports whether the operator explicitly named a config
// path that resolves to a .toml FILE (vs a directory). Only a missing named FILE
// is config.not_found; a missing config.toml inside a named directory is the
// fresh case (§7.3). The flag wins over the env, mirroring ResolvePaths.
func userNamedConfigFile(f FlagValues) bool {
	override := f.Config
	if override == "" {
		override = envOr("DAXIE_CONFIG")
	}
	if override == "" {
		return false // platform default → fresh case
	}
	return strings.EqualFold(filepath.Ext(override), ".toml")
}

// checkSchema refuses a newer major (§7.10). A missing/zero schema is treated as
// the current version (a hand-written file may omit it).
func checkSchema(raw map[string]any, file string) error {
	v, ok := raw["schema"]
	if !ok {
		return nil
	}
	n, err := toInt(v)
	if err != nil {
		return domain.Newf(domain.CodeConfigInvalid,
			"config %s: schema must be an integer, got %v", file, v)
	}
	if n > SchemaVersion {
		return domain.Newf(domain.CodeConfigSchemaUnsupported,
			"config %s has schema %d but this daxie understands at most %d; upgrade daxie",
			file, n, SchemaVersion)
	}
	return nil
}

// newViper builds the per-Load Viper with the DAXIE_* env mapping. Defaults are
// NOT registered in Viper (the built-in Config is the base we unmarshal over);
// Viper here only layers file + env on top.
func newViper() *viper.Viper {
	v := viper.New()
	v.SetConfigType("toml")
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	return v
}

// registerDefaults seeds Viper with the compiled-in scalar defaults so that
// (a) an omitted key keeps its built-in value and (b) an env override
// (AutomaticEnv) participates in Unmarshal (a key must be known for Viper to
// surface its env value through AllSettings). networks/rpc are excluded — they
// are merged manually (mergeNetworksAndRPC). Durations are registered as their
// typed time.Duration values (the decode hook passes non-strings through).
func registerDefaults(v *viper.Viper) {
	d := builtinDefaults()
	v.SetDefault("schema", d.Schema)
	v.SetDefault("defaults.network", d.Defaults.Network)

	v.SetDefault("gas.limit-multiplier", d.Gas.LimitMultiplier)
	v.SetDefault("gas.fee-history-blocks", d.Gas.FeeHistoryBlocks)
	v.SetDefault("gas.speed", d.Gas.Speed)
	v.SetDefault("gas.base-fee-multiplier", d.Gas.BaseFeeMultiplier)
	v.SetDefault("gas.min-priority-fee", d.Gas.MinPriorityFee)
	v.SetDefault("gas.rbf-bump-percent", d.Gas.RBFBumpPercent)
	v.SetDefault("gas.drift-tolerance", d.Gas.DriftTolerance)

	v.SetDefault("tx.wait", d.Tx.Wait)
	v.SetDefault("tx.wait-timeout", d.Tx.WaitTimeout)
	v.SetDefault("tx.poll-interval", d.Tx.PollInterval)
	v.SetDefault("tx.lock-timeout", d.Tx.LockTimeout)

	v.SetDefault("receive.timeout", d.Receive.Timeout)
	v.SetDefault("receive.poll-interval", d.Receive.PollInterval)
	v.SetDefault("receive.max-log-range", d.Receive.MaxLogRange)
	v.SetDefault("receive.heartbeat-interval", d.Receive.HeartbeatInterval)
	v.SetDefault("receive.lookback-blocks", d.Receive.LookbackBlocks)

	v.SetDefault("ens.enabled", d.ENS.Enabled)
}

// applyFile feeds the raw file map into Viper so env can override file scalar
// keys. Excluded:
//   - policy.*  — never Viper-resolved (§4.6).
//   - networks.* / rpc.* — merged manually field-by-field over the built-ins so
//     the sparse-override + geth value-type semantics are exact (mergeNetworks-
//     AndRPC); letting Viper unmarshal them would replace the built-in tables.
func applyFile(v *viper.Viper, raw map[string]any, present bool) error {
	if !present {
		return nil
	}
	clean := make(map[string]any, len(raw))
	for k, val := range raw {
		switch k {
		case "policy", "networks", "rpc":
			continue
		}
		clean[k] = val
	}
	return v.MergeConfigMap(clean)
}

// durationType / addressType are the target types the decode hook converts into.
var (
	durationType = reflect.TypeOf(time.Duration(0))
	addressType  = reflect.TypeOf(common.Address{})
)

// stringConvertHook is a mapstructure DecodeHookFuncType: it converts a string
// source into time.Duration ("10m") or common.Address (hex) when the destination
// field is one of those types, and passes everything else through unchanged. A
// bad value becomes config.invalid (caught once, at load). Passed to
// viper.DecodeHook by value so we need not import the mapstructure package.
func stringConvertHook(from, to reflect.Type, data any) (any, error) {
	if from.Kind() != reflect.String {
		return data, nil
	}
	s, _ := data.(string)
	switch to {
	case durationType:
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, domain.Newf(domain.CodeConfigInvalid, "invalid duration %q: %v", s, err)
		}
		return d, nil
	case addressType:
		if s == "" {
			return common.Address{}, nil
		}
		if !common.IsHexAddress(s) {
			return nil, domain.Newf(domain.CodeConfigInvalid, "invalid address %q", s)
		}
		return common.HexToAddress(s), nil
	default:
		return data, nil
	}
}
