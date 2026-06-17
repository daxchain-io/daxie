package config

import (
	"sort"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// networks.go holds the `daxie network` config mutators + accessors (§6, §7.4,
// cli-spec §network). A network is a CHAIN (name, chain-id, native symbol,
// confirmations) — it says nothing about how to reach the chain; that is an
// endpoint (rpc.go). mainnet + sepolia are built in (builtins.go) and a
// [networks.<name>] file table is a sparse override; user networks are added
// whole. Every mutator funnels through write.mutateRaw so the lock / dir-create /
// read-only discipline (config.read_only on a RO mount, §2.11) lives in one place.

// builtinNetworkNames is the set of compiled-in network names. A built-in network
// is immutable-as-an-object (cannot be removed); its FIELDS may still be overridden
// via a [networks.<name>] table.
var builtinNetworkNames = map[string]bool{"mainnet": true, "sepolia": true}

// NetworkView is the config-owned render shape for one network (strings/ints only;
// no geth behavioral types leak through). service re-maps it into
// domain.NetworkRow so the cli never imports config (the arch matrix). Builtin
// marks a compiled-in preset; Default marks the current defaults.network.
type NetworkView struct {
	Name          string
	ChainID       uint64
	Confirmations uint
	DefaultRPC    string
	Legacy        bool
	NativeSymbol  string
	ENSRegistry   string // EIP-55 hex; "" when zero
	Builtin       bool
	Default       bool
}

// ListNetworks returns every merged network (built-in + file overrides + user
// networks), sorted by name, with the built-in and default markers set.
func (c *Config) ListNetworks() []NetworkView {
	out := make([]NetworkView, 0, len(c.Networks))
	for name, n := range c.Networks {
		out = append(out, c.networkView(name, n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ShowNetwork returns one network by name, or ref.not_found.
func (c *Config) ShowNetwork(name string) (NetworkView, error) {
	n, ok := c.Networks[name]
	if !ok {
		return NetworkView{}, domain.Newf(domain.CodeRefNotFound, "no network named %q", name)
	}
	return c.networkView(name, n), nil
}

// networkView builds the render shape for one merged network.
func (c *Config) networkView(name string, n Network) NetworkView {
	v := NetworkView{
		Name:          name,
		ChainID:       n.ChainID,
		Confirmations: n.Confirmations,
		DefaultRPC:    n.DefaultRPC,
		Legacy:        n.Legacy,
		NativeSymbol:  n.NativeSymbol,
		Builtin:       builtinNetworkNames[name],
		Default:       name == c.Defaults.Network,
	}
	if n.ENSRegistry != (common.Address{}) {
		v.ENSRegistry = n.ENSRegistry.Hex()
	}
	return v
}

// AddNetwork defines a new chain (cli-spec §network). It rejects an empty/invalid
// name, a name colliding with an existing network (usage.network_exists; a
// built-in collision is also network_exists since the object already exists), and
// a zero chain-id. When rpcURL != "" it ALSO creates an endpoint "<name>-default"
// bound to the network and points the network's default-rpc at it (the
// convenience documented in cli-spec §network). The url is stored RAW (any ${…}
// ref stays embedded, §7.5).
func AddNetwork(p Paths, name string, n Network, rpcURL string) error {
	if !validObjectName(name) {
		return invalidName("network", name)
	}
	if n.ChainID == 0 {
		return domain.Newf(domain.CodeUsage+".bad_value",
			"network %q requires a non-zero --chain-id", name)
	}
	defaultEP := name + "-default"
	return mutateRaw(p, func(raw map[string]any) error {
		if networkExistsRaw(raw, name) || builtinNetworkNames[name] {
			return domain.Newf(domain.CodeUsageNetworkExists,
				"network %q already exists", name)
		}
		base := "networks." + name + "."
		setNested(raw, base+"chain-id", int64(n.ChainID)) // #nosec G115 -- chain-id fits int64
		if n.Confirmations != 0 {
			setNested(raw, base+"confirmations", int64(n.Confirmations)) // #nosec G115 -- confirmations is a small block count, fits int64
		}
		if n.NativeSymbol != "" {
			setNested(raw, base+"native-symbol", n.NativeSymbol)
		}
		if n.Legacy {
			setNested(raw, base+"legacy", true)
		}
		if rpcURL != "" {
			ep := "rpc." + defaultEP + "."
			setNested(raw, ep+"network", name)
			setNested(raw, ep+"url", rpcURL) // RAW
			setNested(raw, base+"default-rpc", defaultEP)
		}
		return nil
	})
}

// UseNetwork sets defaults.network (cli-spec §network use). It refuses an unknown
// network (ref.not_found, checked against the MERGED set including built-ins) and
// maps a read-only mount to config.read_only (§2.11). The known-set is passed in
// by the caller (service holds the merged *Config); to keep this a pure config
// mutator the check reads the raw file PLUS the built-in names.
func UseNetwork(p Paths, name string, known map[string]bool) error {
	if !known[name] {
		return domain.Newf(domain.CodeRefNotFound,
			"no network named %q; add it with `daxie network add` first", name)
	}
	return mutateRaw(p, func(raw map[string]any) error {
		setNested(raw, "defaults.network", name)
		return nil
	})
}

// RemoveNetwork removes a USER network (cli-spec §network remove). It refuses a
// built-in (usage.builtin_immutable) and refuses a network still referenced by an
// endpoint unless force (usage.network_in_use). It also clears defaults.network if
// it pointed at the removed network (falling back to the built-in mainnet on next
// load). referencing is the set of endpoint names bound to the network, supplied
// by the caller from the merged *Config.
func RemoveNetwork(p Paths, name string, force bool, referencing []string) error {
	if builtinNetworkNames[name] {
		return domain.Newf(domain.CodeUsageBuiltinImmutable,
			"network %q is built in and cannot be removed", name)
	}
	return mutateRaw(p, func(raw map[string]any) error {
		if !networkExistsRaw(raw, name) {
			return domain.Newf(domain.CodeRefNotFound, "no network named %q", name)
		}
		if len(referencing) > 0 && !force {
			return domain.WithData(
				domain.Newf(domain.CodeUsageNetworkInUse,
					"network %q is still referenced by %d endpoint(s); remove them or pass --force",
					name, len(referencing)),
				map[string]any{"endpoints": referencing},
			)
		}
		deleteNested(raw, "networks."+name)
		// If defaults.network pointed here, clear it (load falls back to the
		// built-in default "mainnet").
		if defs := rawSubTable(raw, "defaults"); defs != nil {
			if cur, _ := defs["network"].(string); cur == name {
				deleteNested(raw, "defaults.network")
			}
		}
		return nil
	})
}

// networkExistsRaw reports whether the file defines [networks.<name>].
func networkExistsRaw(raw map[string]any, name string) bool {
	return rawSubTable(raw, "networks", name) != nil
}

// validObjectName enforces the §3.1 storage grammar reused for network/endpoint
// names: [a-z0-9][a-z0-9_-]{0,63} — kebab-case, lowercase, no dots (the name
// becomes a TOML table key) and no whitespace.
func validObjectName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
			if i == 0 {
				return false // must start with [a-z0-9]
			}
		default:
			return false
		}
	}
	return true
}

// invalidName builds the usage error for a malformed network/endpoint name.
func invalidName(kind, name string) error {
	return domain.Newf(domain.CodeUsage+".bad_name",
		"%s name %q is invalid; use lowercase letters, digits, '-' and '_' (start with a letter or digit, max 64 chars)",
		kind, name)
}
