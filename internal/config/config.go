// Package config owns the config file format and schema, the DAXIE_* env
// mapping and Viper precedence, the four state-class paths across platforms
// (including Windows), the network/RPC-endpoint objects, the secret-reference
// resolver, and the read-only-config behavior (§7).
//
// Viper lives HERE and nowhere else (§2.2 rule 5): the cli frontend binds pflags
// and hands this package a plain FlagValues struct. config is a provider leaf —
// it imports domain (errors), fsx (atomic write + perms), and the geth common
// value type, but never service, a frontend, or chain (§7.5).
package config

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// SchemaVersion is the config-file schema major this build understands. A file
// with a newer major is refused (config.schema_unsupported); a lower known
// version migrates forward on first write (§7.10).
const SchemaVersion = 1

// Config is the immutable, fully-merged configuration produced by Load
// (built-in defaults -> file -> env -> flags, then unmarshaled). The policy.*
// subtree is excluded entirely (§4.6) and the four path roots are NOT here —
// they are resolved pre-Viper and returned separately as Paths (§7.3).
type Config struct {
	Schema   int                 `mapstructure:"schema"`
	Defaults Defaults            `mapstructure:"defaults"`
	Gas      GasDefaults         `mapstructure:"gas"`
	Tx       TxDefaults          `mapstructure:"tx"`
	Receive  ReceiveDefaults     `mapstructure:"receive"`
	ENS      ENSConfig           `mapstructure:"ens"`
	MCP      map[string]any      `mapstructure:"mcp"` // preserved verbatim (v1.1)
	Networks map[string]Network  `mapstructure:"networks"`
	RPC      map[string]Endpoint `mapstructure:"rpc"`

	// sources records, per operator-visible key, where the effective value came
	// from ("default"|"file"|"env"|"flag"). Populated by Load; consumed by
	// ListKeys. Unexported so it never serializes and is not a wire field.
	sources map[string]string `mapstructure:"-"`
}

// Defaults holds top-level default selections.
type Defaults struct {
	Network string `mapstructure:"network"`
}

// GasDefaults is the global gas strategy (§5.4). The *-multiplier keys are
// float64 — this is OPERATOR CONFIG, not a value-math wire type, so float is
// allowed here (the §2.5 no-float rule applies to request/result/value types,
// not config). Fee floors (min-priority-fee) stay strings so the operator writes
// "0.01gwei" and the value is resolved exactly in core.
type GasDefaults struct {
	LimitMultiplier   float64 `mapstructure:"limit-multiplier"`
	FeeHistoryBlocks  int     `mapstructure:"fee-history-blocks"`
	Speed             string  `mapstructure:"speed"`
	BaseFeeMultiplier float64 `mapstructure:"base-fee-multiplier"`
	MinPriorityFee    string  `mapstructure:"min-priority-fee"`
	RBFBumpPercent    float64 `mapstructure:"rbf-bump-percent"`
	DriftTolerance    float64 `mapstructure:"drift-tolerance"`
}

// TxDefaults holds default send/wait behavior. Durations are time.Duration via
// the mapstructure string->duration hook installed in Load.
type TxDefaults struct {
	Wait         bool          `mapstructure:"wait"`
	WaitTimeout  time.Duration `mapstructure:"wait-timeout"`
	PollInterval time.Duration `mapstructure:"poll-interval"`
	LockTimeout  time.Duration `mapstructure:"lock-timeout"`
}

// ReceiveDefaults holds default `daxie receive` behavior (§5.8).
type ReceiveDefaults struct {
	Timeout           time.Duration `mapstructure:"timeout"`
	PollInterval      time.Duration `mapstructure:"poll-interval"`
	MaxLogRange       int           `mapstructure:"max-log-range"`
	HeartbeatInterval time.Duration `mapstructure:"heartbeat-interval"`
	LookbackBlocks    int           `mapstructure:"lookback-blocks"`
}

// ENSConfig toggles ENS resolution.
type ENSConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// Network is a chain definition. Mainnet + Sepolia are built in (builtins.go)
// and a [networks.<name>] table is a sparse field-by-field override over the
// built-in (§7.4). Gas is nil to inherit the global [gas] strategy.
type Network struct {
	ChainID       uint64         `mapstructure:"chain-id"`
	Confirmations uint           `mapstructure:"confirmations"`
	DefaultRPC    string         `mapstructure:"default-rpc"`
	Legacy        bool           `mapstructure:"legacy"`
	NativeSymbol  string         `mapstructure:"native-symbol"`
	ENSRegistry   common.Address `mapstructure:"ens-registry"`
	Gas           *GasDefaults   `mapstructure:"gas"`
}

// Endpoint is a named RPC connection bound to a network. URLRef keeps the RAW
// value with any ${env:}/${file:} references still embedded — config NEVER
// resolves them (that happens transiently in service at dial time, §7.5).
type Endpoint struct {
	Network string            `mapstructure:"network"`
	URLRef  string            `mapstructure:"url"`
	Headers map[string]string `mapstructure:"headers"`
	TLS     *TLSFiles         `mapstructure:"tls"`
	Timeout time.Duration     `mapstructure:"timeout"`
}

// TLSFiles are mTLS file PATHS (not secret references); the key file is
// permission-checked like a passphrase file (§7.5).
type TLSFiles struct {
	Cert string `mapstructure:"cert"`
	Key  string `mapstructure:"key"`
	CA   string `mapstructure:"ca"`
}
