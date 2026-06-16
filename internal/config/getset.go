package config

import (
	"strconv"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
)

// KV is one operator-visible config key with its effective value and the layer
// the value came from (§7.3 config list).
type KV struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"` // "default"|"file"|"env"|"flag"
}

// scalarKeys is the canonical, ordered set of operator-visible scalar config
// keys (§7.4). The five path vars are deliberately ABSENT (resolved pre-Viper,
// never config keys, §7.3) and the policy.* subtree is ABSENT (out of scope
// here, §7.6). Networks/RPC are object tables (managed by `network`/`rpc`
// commands), not listed as scalar keys.
var scalarKeys = []string{
	"defaults.network",
	"gas.limit-multiplier",
	"gas.fee-history-blocks",
	"gas.speed",
	"gas.base-fee-multiplier",
	"gas.min-priority-fee",
	"gas.rbf-bump-percent",
	"gas.drift-tolerance",
	"tx.wait",
	"tx.wait-timeout",
	"tx.poll-interval",
	"tx.lock-timeout",
	"receive.timeout",
	"receive.poll-interval",
	"receive.max-log-range",
	"receive.heartbeat-interval",
	"receive.lookback-blocks",
	"ens.enabled",
}

// scalarKeySet is the membership view of scalarKeys.
var scalarKeySet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(scalarKeys))
	for _, k := range scalarKeys {
		m[k] = struct{}{}
	}
	return m
}()

// ListKeys returns the operator-visible config keys with their effective values
// and provenance, in a stable order (§7.3). Path vars and policy.* are excluded.
func (c *Config) ListKeys() []KV {
	out := make([]KV, 0, len(scalarKeys))
	for _, k := range scalarKeys {
		src := "default"
		if c.sources != nil {
			if s, ok := c.sources[k]; ok {
				src = s
			}
		}
		out = append(out, KV{Key: k, Value: c.keyValue(k), Source: src})
	}
	return out
}

// GetKey returns one key's effective value, or ref.not_found for an unknown key.
// A policy.* key is rejected with usage.* (it is never readable here, §7.6).
func (c *Config) GetKey(key string) (string, error) {
	if isPolicyKey(key) {
		return "", domain.Newf(domain.CodeUsage+".policy_key",
			"%q is a policy key — inspect with `daxie policy show`, not `config get`", key)
	}
	if _, ok := scalarKeySet[key]; !ok {
		return "", domain.Newf(domain.CodeRefNotFound, "unknown config key %q", key)
	}
	return c.keyValue(key), nil
}

// keyValue renders one scalar key's effective value as a string.
func (c *Config) keyValue(key string) string {
	switch key {
	case "defaults.network":
		return c.Defaults.Network
	case "gas.limit-multiplier":
		return ftoa(c.Gas.LimitMultiplier)
	case "gas.fee-history-blocks":
		return strconv.Itoa(c.Gas.FeeHistoryBlocks)
	case "gas.speed":
		return c.Gas.Speed
	case "gas.base-fee-multiplier":
		return ftoa(c.Gas.BaseFeeMultiplier)
	case "gas.min-priority-fee":
		return c.Gas.MinPriorityFee
	case "gas.rbf-bump-percent":
		return ftoa(c.Gas.RBFBumpPercent)
	case "gas.drift-tolerance":
		return ftoa(c.Gas.DriftTolerance)
	case "tx.wait":
		return strconv.FormatBool(c.Tx.Wait)
	case "tx.wait-timeout":
		return c.Tx.WaitTimeout.String()
	case "tx.poll-interval":
		return c.Tx.PollInterval.String()
	case "tx.lock-timeout":
		return c.Tx.LockTimeout.String()
	case "receive.timeout":
		return c.Receive.Timeout.String()
	case "receive.poll-interval":
		return c.Receive.PollInterval.String()
	case "receive.max-log-range":
		return strconv.Itoa(c.Receive.MaxLogRange)
	case "receive.heartbeat-interval":
		return c.Receive.HeartbeatInterval.String()
	case "receive.lookback-blocks":
		return strconv.Itoa(c.Receive.LookbackBlocks)
	case "ens.enabled":
		return strconv.FormatBool(c.ENS.Enabled)
	default:
		return ""
	}
}

// valueType classifies a scalar key's value type for set-time validation.
type valueType int

const (
	typeString valueType = iota
	typeBool
	typeInt
	typeFloat
	typeDuration
	typeFee // fee-with-unit string, e.g. "0.01gwei"
)

// keyType returns the value type expected for a scalar key.
func keyType(key string) valueType {
	switch key {
	case "defaults.network", "gas.speed":
		return typeString
	case "gas.min-priority-fee":
		return typeFee
	case "gas.limit-multiplier", "gas.base-fee-multiplier",
		"gas.rbf-bump-percent", "gas.drift-tolerance":
		return typeFloat
	case "gas.fee-history-blocks", "receive.max-log-range", "receive.lookback-blocks":
		return typeInt
	case "tx.wait", "ens.enabled":
		return typeBool
	case "tx.wait-timeout", "tx.poll-interval", "tx.lock-timeout",
		"receive.timeout", "receive.poll-interval", "receive.heartbeat-interval":
		return typeDuration
	default:
		return typeString
	}
}

// isPolicyKey reports whether a key is in the policy.* subtree (never settable
// or gettable via `config`, §7.6).
func isPolicyKey(key string) bool {
	return key == "policy" || strings.HasPrefix(key, "policy.")
}

// ftoa renders a float64 config value without scientific notation and without a
// trailing ".0" (so 1.2 -> "1.2", 2.0 -> "2").
func ftoa(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
