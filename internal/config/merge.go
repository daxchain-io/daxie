package config

import (
	"fmt"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// mergeNetworksAndRPC overlays the file's [networks.*] and [rpc.*] tables onto
// the built-in maps already in cfg (§7.4). A file table is a SPARSE override:
// only the fields it actually sets replace the built-in; absent fields keep the
// built-in value. A user-added network/endpoint (not built in) is added whole.
//
// This is done from the raw file map (not via Viper) so the geth common.Address
// value type and the inherit-vs-override semantics are exact.
func mergeNetworksAndRPC(cfg *Config, raw map[string]any) error {
	if raw == nil {
		return nil
	}
	if nraw, ok := raw["networks"].(map[string]any); ok {
		for name, t := range nraw {
			tbl, ok := t.(map[string]any)
			if !ok {
				return domain.Newf(domain.CodeConfigInvalid,
					"[networks.%s] is not a table", name)
			}
			base := cfg.Networks[name] // zero value if user-added
			if err := overlayNetwork(&base, tbl, name); err != nil {
				return err
			}
			cfg.Networks[name] = base
		}
	}
	if rraw, ok := raw["rpc"].(map[string]any); ok {
		for name, t := range rraw {
			tbl, ok := t.(map[string]any)
			if !ok {
				return domain.Newf(domain.CodeConfigInvalid,
					"[rpc.%s] is not a table", name)
			}
			base := cfg.RPC[name]
			if err := overlayEndpoint(&base, tbl, name); err != nil {
				return err
			}
			cfg.RPC[name] = base
		}
	}
	return nil
}

// overlayNetwork applies the set fields of a [networks.<name>] table over n.
func overlayNetwork(n *Network, tbl map[string]any, name string) error {
	for k, v := range tbl {
		switch k {
		case "chain-id":
			id, err := toUint64(v)
			if err != nil {
				return fieldErr("networks", name, k, v)
			}
			n.ChainID = id
		case "confirmations":
			c, err := toUint64(v)
			if err != nil {
				return fieldErr("networks", name, k, v)
			}
			n.Confirmations = uint(c)
		case "default-rpc":
			s, err := toStr(v)
			if err != nil {
				return fieldErr("networks", name, k, v)
			}
			n.DefaultRPC = s
		case "legacy":
			b, ok := v.(bool)
			if !ok {
				return fieldErr("networks", name, k, v)
			}
			n.Legacy = b
		case "native-symbol":
			s, err := toStr(v)
			if err != nil {
				return fieldErr("networks", name, k, v)
			}
			n.NativeSymbol = s
		case "ens-registry":
			s, err := toStr(v)
			if err != nil || !common.IsHexAddress(s) {
				return fieldErr("networks", name, k, v)
			}
			n.ENSRegistry = common.HexToAddress(s)
		case "gas":
			gtbl, ok := v.(map[string]any)
			if !ok {
				return fieldErr("networks", name, k, v)
			}
			g := GasDefaults{}
			if n.Gas != nil {
				g = *n.Gas
			}
			if err := overlayGas(&g, gtbl, name); err != nil {
				return err
			}
			n.Gas = &g
		default:
			// Unknown keys are ignored (forward-compat), matching the
			// "unknown keys survive" config posture (§7.4).
		}
	}
	return nil
}

// overlayGas applies the set fields of a per-network [networks.<name>.gas] table.
func overlayGas(g *GasDefaults, tbl map[string]any, net string) error {
	for k, v := range tbl {
		switch k {
		case "limit-multiplier":
			f, err := toFloat(v)
			if err != nil {
				return fieldErr("networks."+net, "gas", k, v)
			}
			g.LimitMultiplier = f
		case "fee-history-blocks":
			i, err := toInt(v)
			if err != nil {
				return fieldErr("networks."+net, "gas", k, v)
			}
			g.FeeHistoryBlocks = i
		case "speed":
			s, err := toStr(v)
			if err != nil {
				return fieldErr("networks."+net, "gas", k, v)
			}
			g.Speed = s
		case "base-fee-multiplier":
			f, err := toFloat(v)
			if err != nil {
				return fieldErr("networks."+net, "gas", k, v)
			}
			g.BaseFeeMultiplier = f
		case "min-priority-fee":
			s, err := toStr(v)
			if err != nil {
				return fieldErr("networks."+net, "gas", k, v)
			}
			g.MinPriorityFee = s
		case "rbf-bump-percent":
			f, err := toFloat(v)
			if err != nil {
				return fieldErr("networks."+net, "gas", k, v)
			}
			g.RBFBumpPercent = f
		case "drift-tolerance":
			f, err := toFloat(v)
			if err != nil {
				return fieldErr("networks."+net, "gas", k, v)
			}
			g.DriftTolerance = f
		}
	}
	return nil
}

// overlayEndpoint applies the set fields of a [rpc.<name>] table over e.
func overlayEndpoint(e *Endpoint, tbl map[string]any, name string) error {
	for k, v := range tbl {
		switch k {
		case "network":
			s, err := toStr(v)
			if err != nil {
				return fieldErr("rpc", name, k, v)
			}
			e.Network = s
		case "url":
			s, err := toStr(v)
			if err != nil {
				return fieldErr("rpc", name, k, v)
			}
			e.URLRef = s // RAW; ${env:}/${file:} refs stay embedded (§7.5)
		case "timeout":
			s, err := toStr(v)
			if err != nil {
				return fieldErr("rpc", name, k, v)
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return fieldErr("rpc", name, k, v)
			}
			e.Timeout = d
		case "headers":
			htbl, ok := v.(map[string]any)
			if !ok {
				return fieldErr("rpc", name, k, v)
			}
			if e.Headers == nil {
				e.Headers = map[string]string{}
			}
			for hk, hv := range htbl {
				s, err := toStr(hv)
				if err != nil {
					return fieldErr("rpc."+name, "headers", hk, hv)
				}
				e.Headers[hk] = s // RAW refs stay embedded
			}
		case "tls":
			ttbl, ok := v.(map[string]any)
			if !ok {
				return fieldErr("rpc", name, k, v)
			}
			tls := &TLSFiles{}
			if e.TLS != nil {
				tls = e.TLS
			}
			for tk, tv := range ttbl {
				s, err := toStr(tv)
				if err != nil {
					return fieldErr("rpc."+name, "tls", tk, tv)
				}
				switch tk {
				case "cert":
					tls.Cert = s
				case "key":
					tls.Key = s
				case "ca":
					tls.CA = s
				}
			}
			e.TLS = tls
		}
	}
	return nil
}

func fieldErr(table, name, key string, v any) error {
	return domain.Newf(domain.CodeConfigInvalid,
		"[%s.%s] key %q has an invalid value %v (%T)", table, name, key, v, v)
}

// ── raw TOML scalar coercions (go-toml decodes ints as int64, floats as
//    float64; we accept the natural TOML types and reject the rest) ──

func toStr(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("not a string")
	}
	return s, nil
}

func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int64:
		return int(n), nil
	case int:
		return n, nil
	default:
		return 0, fmt.Errorf("not an integer")
	}
}

func toUint64(v any) (uint64, error) {
	switch n := v.(type) {
	case int64:
		if n < 0 {
			return 0, fmt.Errorf("negative")
		}
		return uint64(n), nil
	case int:
		if n < 0 {
			return 0, fmt.Errorf("negative")
		}
		return uint64(n), nil
	default:
		return 0, fmt.Errorf("not an integer")
	}
}

func toFloat(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case int64:
		return float64(n), nil
	case int:
		return float64(n), nil
	default:
		return 0, fmt.Errorf("not a number")
	}
}
