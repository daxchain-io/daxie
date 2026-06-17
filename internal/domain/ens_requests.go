package domain

// ens_requests.go carries the wire types for `daxie ens resolve|reverse` (cli-spec
// §`daxie ens`, design §2.8/§4.8). Resolution is per-invocation against the
// connected network's ENS registry; the resolved address is the load-bearing field
// (an agent/human must see what a name actually points to before trusting it). No
// float, every value a string on the wire (§2.5).

// EnsResolveRequest is `daxie ens resolve <name>`: forward-resolve an ENS name to
// its address on the selected network. Network/RPC choose the endpoint per call
// (§2.8) so the same name on mainnet vs Sepolia resolves independently.
type EnsResolveRequest struct {
	Name    string `json:"name" jsonschema:"the ENS name to resolve, e.g. vitalik.eth"`
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// EnsResolveResult is the forward-lookup answer: name → address. Address is the
// checksummed 0x string; it is empty only on the error path (an unresolved name is
// a clean ens error, never an all-zero address echoed as success).
type EnsResolveResult struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Network string `json:"network"`
}

// EnsReverseRequest is `daxie ens reverse <addr>`: reverse-resolve an address to its
// primary ENS name on the selected network. The result is FORWARD-VERIFIED — a
// reverse name is only trusted when it forward-resolves back to the address (§4.8
// pin safety), so an unverified record yields an empty name + Verified=false.
type EnsReverseRequest struct {
	Address string `json:"address" jsonschema:"the 0x address to reverse-resolve"`
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// EnsReverseResult is the reverse-lookup answer: address → primary name. Name is
// non-empty only when Verified (the reverse record forward-resolves back to the
// address); an address with no trusted primary name returns Name=="" Verified=false
// so callers never display a reverse name that does not round-trip.
type EnsReverseResult struct {
	Address  string `json:"address"`
	Name     string `json:"name,omitempty"`
	Verified bool   `json:"verified"`
	Network  string `json:"network"`
}
