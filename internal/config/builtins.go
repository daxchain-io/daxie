package config

import "github.com/ethereum/go-ethereum/common"

// mainnetENSRegistry is the canonical ENS registry on mainnet and Sepolia
// (same address on both, §7.4).
var ensRegistry = common.HexToAddress("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e")

// builtinNetworks returns a fresh copy of the compiled-in network definitions
// (§7.4). Mainnet and Sepolia are NOT written to a fresh config file; a
// [networks.<name>] table in config.toml is a sparse field-by-field override
// merged over these. A fresh map is returned each call so callers may mutate it.
func builtinNetworks() map[string]Network {
	return map[string]Network{
		"mainnet": {
			ChainID:       1,
			Confirmations: 2, // mainnet --wait default (§5)
			DefaultRPC:    "mainnet-public",
			NativeSymbol:  "ETH",
			ENSRegistry:   ensRegistry,
		},
		"sepolia": {
			ChainID:       11155111,
			Confirmations: 1,
			DefaultRPC:    "sepolia-public",
			NativeSymbol:  "ETH",
			ENSRegistry:   ensRegistry,
		},
	}
}

// builtinRPC returns the compiled-in default public RPC endpoints (§7.4). These
// are intentionally rate-limited community endpoints; docs steer serious use to
// a user-supplied endpoint (rpc list flags them).
func builtinRPC() map[string]Endpoint {
	return map[string]Endpoint{
		"mainnet-public": {
			Network: "mainnet",
			URLRef:  "https://ethereum-rpc.publicnode.com",
		},
		"sepolia-public": {
			Network: "sepolia",
			URLRef:  "https://ethereum-sepolia-rpc.publicnode.com",
		},
	}
}

// builtinDefaults returns the compiled-in scalar defaults that back every config
// key when the file omits it (§7.4). This is the lowest-precedence layer
// (defaults < file < env < flags).
func builtinDefaults() Config {
	return Config{
		Schema:   SchemaVersion,
		Defaults: Defaults{Network: "mainnet"},
		Gas: GasDefaults{
			LimitMultiplier:   1.2,
			FeeHistoryBlocks:  20,
			Speed:             "normal",
			BaseFeeMultiplier: 2.0,
			MinPriorityFee:    "0.01gwei",
			RBFBumpPercent:    12.5,
			DriftTolerance:    0.10,
		},
		Tx: TxDefaults{
			Wait:         false,
			WaitTimeout:  mustDur("10m"),
			PollInterval: mustDur("4s"),
			LockTimeout:  mustDur("30s"),
		},
		Receive: ReceiveDefaults{
			Timeout:           0, // 0 = listen forever (deliberately not inheriting tx.wait-timeout)
			PollInterval:      mustDur("4s"),
			MaxLogRange:       1000,
			HeartbeatInterval: mustDur("60s"),
			LookbackBlocks:    0,
		},
		ENS:      ENSConfig{Enabled: true},
		MCP:      map[string]any{},
		Networks: builtinNetworks(),
		RPC:      builtinRPC(),
	}
}
