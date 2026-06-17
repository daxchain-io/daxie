// Package mcpserver is Frontend 2: the Model Context Protocol server over the
// SAME *service.Service the Cobra frontend (internal/cli) drives. It is the
// executable proof of the one-core/two-frontends architecture (design §1a, §6):
// every tool handler is `args → the SAME domain request struct → the SAME
// service method → result`, ~20 lines, with ZERO business logic. It physically
// cannot contain business logic — the arch matrix denies it the provider imports
// (policy/keys/chain/erc/ens/registry/journal/abi/secret/config/policyseal) that
// any logic would require. It imports ONLY service + domain (+ version), exactly
// like cli, plus the third-party MCP SDK and stdlib net/http+crypto/tls for the
// reserved v1.1 transport seam.
//
// The central guarantee (design §6.4): guardrails bind MCP IDENTICALLY because
// every write tool routes through the same svc.* method — the only path to
// domain.Signer, with policy.Reserve + the seal/allowlist/ENS-pin/gas-cap/
// unlimited checks INSIDE it. mcpserver cannot import policy or keys, so it has
// no way to skip the check. A prompt-injected agent cannot raise its own limits,
// exfiltrate a key, or redefine an alias through the tool channel — the §6.1
// exclusion boundary (NO policy mutation, key export/import/create, account
// derive/alias/use, keystore change-passphrase, network/rpc mutation, or *_add
// registry mutation) is real and complete.
//
// Transport abstraction (design §6.8): New(svc) builds the transport-agnostic
// *mcp.Server ONCE (registers all 31 tools via tools.Register) and never changes
// when a transport is added. ServeStdio is the v1 wiring; Serve is the
// --transport switch (stdio served, http REJECTED in v1 with a forward-pointing
// domain.Error). ServeHTTP + HTTPOptions are the reserved v1.1 seam (declared so
// the Authenticator/Principal hook has a home; the body refuses in v1). v1 builds
// none of HTTP, auth, or per-principal policy — it builds the seams that make
// them additive (a new enum value + a new-file body, not a refactor).
//
// Error model (design §6.6): one domain.Error taxonomy, two renderings. The tools
// subpackage's toolError passes a *domain.Error straight through; the SDK packs it
// into the tool-error envelope (IsError) with the JSON byte-identical to the CLI
// --json error. The dual-signal cases (tx.reverted / tx.wait_timeout /
// tx.nonce_gap) that need BOTH IsError AND the structured *domain.TxResult return a
// nil Go error with a hand-built IsError result so the SDK still fills
// StructuredContent.
//
// Progress (design §6.5): the tools subpackage's progressSink maps the single
// domain.EventSink onto MCP progress notifications, gated on the client's progress
// token; long-running tools (tx_wait, receive) block and stream. Best-effort: a
// dropped notification never affects the outcome, which is fully captured in the
// return value.
//
// The error-map + progress helpers live in the mcpserver/tools subpackage (the
// handlers call them, and mcpserver imports tools for Register, so tools cannot
// import mcpserver — that subpackage is their cycle-free home). This core package
// owns the transport-agnostic Server assembly (New), the §6.8 transport switch
// (Serve/ServeStdio, http rejected), the reserved v1.1 HTTP+auth seam
// (ServeHTTP/HTTPOptions), and tool introspection (ListTools for `daxie mcp tools`
// and the golden-schema test).
package mcpserver
