package domain

// This file is the wire contract for the M2 network / RPC-endpoint / balance use
// cases (§2.5, §2.6, §2.8, §6, §7.4/§7.5, cli-spec §`daxie network`/§`daxie
// rpc`/§`daxie balance`). Every type obeys the triple-duty rule that already
// governs keys_requests.go:
//
//   - NO float field anywhere (§2.5): chain IDs are uint64, counts are int, every
//     user-facing scalar that could exceed an int64 or carry units (wei, eth) is a
//     decimal STRING assembled over math/big upstream, never a float.
//   - Every user value is a string on the wire (addresses, wei, formatted ETH).
//   - json struct tags so the same struct serves the CLI --json output, the MCP
//     tool schema (M11), and the v1.1 HTTP body.
//
// SECRET MATERIAL NEVER APPEARS RESOLVED HERE. An endpoint URL/header may CARRY a
// ${env:}/${file:} reference (the reference is not the secret, §7.5); the resolved
// value lives only transiently in service at dial time and never reaches a request
// or result struct. Masking for `rpc show`/`rpc list` happens in config before the
// row is built, so RPCRow.URL is already masked when it crosses this boundary.

// Speed is the gas `--speed` preset (M3 consumes it). It is declared HERE in M2,
// not in a frontend, because the gas engine selects a percentile tier from
// chain.SuggestFees by domain.Speed and a provider (chain) must never depend on a
// frontend (§2.6). Declaring it now keeps the chain.Client interface defined whole
// in M2 (§10.2) without an import cycle.
type Speed string

const (
	// SpeedSlow biases toward a lower fee / longer inclusion time.
	SpeedSlow Speed = "slow"
	// SpeedNormal is the default fee strategy.
	SpeedNormal Speed = "normal"
	// SpeedFast biases toward faster inclusion at a higher fee.
	SpeedFast Speed = "fast"
)

// ─── balance ─────────────────────────────────────────────────────────────────

// BalanceRequest selects an account (or raw address), a network, and an optional
// endpoint override for `daxie balance`. Token/All are flag-plumbed in M2 but the
// service rejects them with usage.unsupported (they land in M5); an ENS Account
// likewise fails clean (M7). Nothing is faked.
type BalanceRequest struct {
	Account string `json:"account,omitempty"` // account ref or raw 0x; "" = default account (§7.7)
	Network string `json:"network,omitempty"` // --network override; "" = config defaults.network
	RPC     string `json:"rpc,omitempty"`     // --rpc endpoint override; "" = the network's default-rpc
	Token   string `json:"token,omitempty"`   // M5 (flag plumbed; M2 rejects usage.unsupported)
	All     bool   `json:"all,omitempty"`     // M5 (flag plumbed; M2 rejects usage.unsupported)
}

// BalanceResult is the balance of one address on one network. For a native (ETH)
// balance Wei/Eth/Symbol carry the value; for a single `--token` read the Token
// block carries the ERC-20 balance (and Wei/Eth stay empty); for `--all` the ETH
// value is in Wei/Eth and every nonzero registry token rides in Tokens. Wei is an
// exact decimal string and Eth a fixed-decimal string (no float anywhere, §2.5).
type BalanceResult struct {
	Address string `json:"address"`           // EIP-55 hex of the resolved account
	Network string `json:"network"`           // the network the balance was read on
	Wei     string `json:"wei,omitempty"`     // exact decimal string (native; empty on a --token-only read)
	Eth     string `json:"eth,omitempty"`     // fixed-decimal string (ethunit.FormatAmount)
	Symbol  string `json:"symbol,omitempty"`  // native symbol, e.g. "ETH"
	Account string `json:"account,omitempty"` // the request ref, when it named a keystore account

	// Token is the single-token (`balance --token <alias|0x>`) ERC-20 balance: the
	// resolved asset block + the exact base-unit string + the decimals-aware human
	// form. Empty for a native or --all read.
	Token *TokenBalance `json:"token,omitempty"`
	// Tokens is the `balance --all` per-token listing: every registry token (bundled
	// majors ∪ file entries) the owner holds a NONZERO balance of, alias-sorted. The
	// ETH value rides in Wei/Eth alongside. Empty for a single read.
	Tokens []TokenBalance `json:"tokens,omitempty"`
}

// ─── network ─────────────────────────────────────────────────────────────────

// NetworkRow is one network's display shape (strings/ints only). Builtin marks a
// compiled-in preset (mainnet/sepolia); Default marks the current defaults.network.
type NetworkRow struct {
	Name          string `json:"name"`
	ChainID       uint64 `json:"chain_id"`
	Confirmations uint   `json:"confirmations"`
	DefaultRPC    string `json:"default_rpc,omitempty"`
	Legacy        bool   `json:"legacy,omitempty"`
	NativeSymbol  string `json:"native_symbol,omitempty"`
	ENSRegistry   string `json:"ens_registry,omitempty"` // EIP-55 hex; "" when unset
	Builtin       bool   `json:"builtin,omitempty"`
	Default       bool   `json:"default,omitempty"`
}

// NetworkAddRequest defines a new chain. RPCURL is the optional --rpc-url
// convenience: when set, `network add` also creates an endpoint "<name>-default"
// bound to the network and points the network's default-rpc at it (cli-spec
// §network).
type NetworkAddRequest struct {
	Name         string `json:"name"`
	ChainID      uint64 `json:"chain_id"`
	RPCURL       string `json:"rpc_url,omitempty"`
	Legacy       bool   `json:"legacy,omitempty"`
	NativeSymbol string `json:"native_symbol,omitempty"`
}

// NetworkUseRequest sets the default network (defaults.network).
type NetworkUseRequest struct {
	Name string `json:"name"`
}

// NetworkRemoveRequest removes a user network. Force is required to remove a
// network that still has endpoints referencing it (cli-spec §network).
type NetworkRemoveRequest struct {
	Name  string `json:"name"`
	Force bool   `json:"-"` // CLI-only --force gate
}

// NetworkShowRequest shows one network by name.
type NetworkShowRequest struct {
	Name string `json:"name"`
}

// NetworkListRequest lists every network (no filter in v1). It mirrors the M1
// list-request convention (every use case takes a request struct) so the MCP/HTTP
// surfaces have a stable input shape even when there are no inputs yet.
type NetworkListRequest struct{}

// NetworkResult wraps one network row (add/show/use).
type NetworkResult struct {
	Network NetworkRow `json:"network"`
}

// NetworkListResult is the network roster.
type NetworkListResult struct {
	Networks []NetworkRow `json:"networks"`
}

// NetworkRemoveResult confirms a network removal.
type NetworkRemoveResult struct {
	Name    string `json:"name"`
	Removed bool   `json:"removed"`
}

// ─── rpc ─────────────────────────────────────────────────────────────────────

// RPCRow is one endpoint's display shape. URL is ALREADY masked when this row is
// built (config.MaskSecretRefs): a ${env:}/${file:} reference is shown as the
// reference (the reference is not the secret) and any literal opaque segment is
// reduced to "***". HasHeaders/HasTLS report auth without leaking values.
type RPCRow struct {
	Name          string `json:"name"`
	Network       string `json:"network"`
	URL           string `json:"url"` // MASKED
	HasHeaders    bool   `json:"has_headers,omitempty"`
	HasTLS        bool   `json:"has_tls,omitempty"`
	Default       bool   `json:"default,omitempty"`        // the network's default-rpc points here
	PublicDefault bool   `json:"public_default,omitempty"` // a built-in public endpoint
}

// RPCAddRequest adds a named endpoint bound to a network. Headers/TLS/Timeout are
// optional. StrictSecrets escalates the literal-secret heuristic from a warning to
// a hard error (§7.5). The URL keeps any ${…} reference RAW — config never
// resolves it.
type RPCAddRequest struct {
	Name          string            `json:"name"`
	Network       string            `json:"network"`
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers,omitempty"`
	TLSCert       string            `json:"tls_cert,omitempty"`
	TLSKey        string            `json:"tls_key,omitempty"`
	TLSCA         string            `json:"tls_ca,omitempty"`
	Timeout       Duration          `json:"timeout,omitempty"`
	StrictSecrets bool              `json:"-"` // CLI-only --strict-secrets gate
}

// RPCUseRequest makes an endpoint the default for its network.
type RPCUseRequest struct {
	Name string `json:"name"`
}

// RPCRenameRequest renames an endpoint.
type RPCRenameRequest struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// RPCRemoveRequest removes an endpoint (and clears a default-rpc that pointed at
// it).
type RPCRemoveRequest struct {
	Name string `json:"name"`
}

// RPCShowRequest shows one endpoint by name (masked).
type RPCShowRequest struct {
	Name string `json:"name"`
}

// RPCListRequest lists endpoints, optionally filtered to one network.
type RPCListRequest struct {
	Network string `json:"network,omitempty"`
}

// RPCTestRequest connects to an endpoint and verifies eth_chainId matches the
// endpoint's network (cli-spec §rpc). Network/RPC carry per-invocation overrides
// when testing an ad-hoc selection rather than a named endpoint.
type RPCTestRequest struct {
	Name    string `json:"name,omitempty"`
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// RPCTestResult reports a successful chain-ID verification and the round-trip
// latency. OK is true only when eth_chainId matched the network (a mismatch is an
// error, not OK=false).
type RPCTestResult struct {
	Name      string `json:"name,omitempty"`
	Network   string `json:"network"`
	ChainID   uint64 `json:"chain_id"`
	LatencyMS int64  `json:"latency_ms"`
	OK        bool   `json:"ok"`
}

// RPCResult wraps one endpoint row plus any non-fatal warnings (the literal-secret
// heuristic emits one on add).
type RPCResult struct {
	RPC      RPCRow   `json:"rpc"`
	Warnings []string `json:"warnings,omitempty"`
}

// RPCListResult is the endpoint roster.
type RPCListResult struct {
	RPCs []RPCRow `json:"rpcs"`
}

// RPCRemoveResult confirms an endpoint removal and reports a default-rpc it
// cleared, if any.
type RPCRemoveResult struct {
	Name                string `json:"name"`
	Removed             bool   `json:"removed"`
	ClearedAsDefaultFor string `json:"cleared_as_default_for,omitempty"` // network whose default-rpc pointed here
}

// ─── new error-code constants ────────────────────────────────────────────────

// These name the M2 leaves the network/rpc/balance surface emits. Their exit
// projections are asserted by chain_requests_test.go against ExitOf so the §5.7
// contract is pinned. Most families already exist in error.go (rpc.*, usage.*,
// ref.not_found, config.read_only, secret.unresolved); only the genuinely new
// leaves below are added here as named constants, and only rpc.unsupported needs a
// codeExit row (added in error.go) — everything else inherits an existing prefix.
const (
	// CodeRPCChainIDMismatch is the malicious/misconfigured-endpoint guard: the
	// endpoint's eth_chainId did not equal its declared network's chain-id. Exit 12
	// (integrity); the codeExit row already exists.
	CodeRPCChainIDMismatch = "rpc.chain_id_mismatch"
	// CodeRPCUnreachable is a dial/transport failure. Exit 6 (network); the codeExit
	// row already exists, and it is retryable.
	CodeRPCUnreachable = "rpc.unreachable"
	// CodeRPCUnsupported is the typed "unsupported on this transport" sentinel
	// Subscribe* return on HTTP (no second interface, §2.6). It is not a user-facing
	// M2 path, but if it ever surfaces it must be honest — error.go maps it to exit 2
	// (usage) so it funnels through §5.7 rather than masquerading as internal.
	CodeRPCUnsupported = "rpc.unsupported"

	// usage.* leaves for the network/rpc command surface (all exit 2 via the usage
	// prefix already in codeExit — no new rows needed):

	// CodeUsageUnsupported is the clean "this lands in a later milestone" rejection
	// (balance --token/--all → M5; an ENS account → M7). NEVER faked.
	CodeUsageUnsupported = "usage.unsupported"
	// CodeUsageRPCNetworkMismatch is a --rpc naming an endpoint bound to a different
	// network than the selected one, or --rpc naming a network (strict separation).
	CodeUsageRPCNetworkMismatch = "usage.rpc_network_mismatch"
	// CodeUsageNetworkExists is `network add` of an already-defined network.
	CodeUsageNetworkExists = "usage.network_exists"
	// CodeUsageRPCExists is `rpc add`/`rpc rename` colliding with an existing
	// endpoint name.
	CodeUsageRPCExists = "usage.rpc_exists"
	// CodeUsageBuiltinImmutable is an attempt to remove a built-in network/endpoint.
	CodeUsageBuiltinImmutable = "usage.builtin_immutable"
	// CodeUsageNetworkInUse is `network remove` of a network still referenced by an
	// endpoint, without --force.
	CodeUsageNetworkInUse = "usage.network_in_use"
	// CodeUsageLiteralSecret is the --strict-secrets escalation of a detected literal
	// secret in a URL/header.
	CodeUsageLiteralSecret = "usage.literal_secret" // #nosec G101 -- error-code identifier string, not a credential
)
