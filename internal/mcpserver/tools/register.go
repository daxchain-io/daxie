// Package tools is the MCP tool surface of Daxie's SECOND thin frontend (design
// §6.1/§6.2/§6.4). It is the executable proof of requirements §1a — "guardrails
// apply identically to MCP-initiated signing" — because every tool handler is the
// same three lines around the same service call the CLI runs: bind the tool args
// into the SAME domain request struct the CLI binds, call the SAME service method,
// return the SAME result struct. There is ZERO business logic here, and there
// cannot be: the arch matrix denies this package the provider imports
// (policy/keys/chain/erc/ens/registry/journal/abi) it would need to do anything a
// service method does not already do. mcpserver/tools imports service + domain +
// the MCP SDK ONLY.
//
// The 31 tools (§6.1) are registered ONCE by Register, called from
// mcpserver.New(svc). Their input/output JSON schemas are INFERRED by the SDK from
// the Go In/Out types — and the In type IS a domain request struct (the CLI binds
// the SAME struct), so CLI/MCP schema drift is impossible by construction (a golden
// test pins the inferred surface, §6.7). The agent-facing descriptions live in
// descriptions.go; the §6.7 golden test pins those too.
//
// The deliberately-NOT-tools security boundary (§6.1) is REAL and complete: there
// is no handler — and no AddTool call — for any policy mutation, key
// export/import/create, account derive/alias/use, keystore change-passphrase,
// network/rpc mutation, or any *_add registry mutation. The boundary is enforced
// by ABSENCE (a prompt-injected agent cannot raise its own limits, exfiltrate a
// key, or redefine an alias through the tool channel) and recorded as a tested
// artifact: ToolNames lists exactly the 31 present; ExcludedTools lists a
// representative denylist of operations that must never appear. Group C's
// server_test asserts the registered set equals ToolNames and is disjoint from
// ExcludedTools.
package tools

import (
	"context"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/service"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Register adds EXACTLY the 31 §6.1 tools to srv, each bound to the same svc the
// CLI frontend uses. It is the ONE place every mcp.AddTool call lives (the handlers
// themselves are grouped into read.go/write.go/stream.go/pure.go for readability,
// but the registration list — the agent-visible contract — is here). The order is
// the §6.1 table order so the registration reads top-to-bottom like the design (the
// SDK lists tools sorted by name, so wire order is not load-bearing).
//
// This is the single coordination contract between Group A (mcpserver.New, which
// calls Register) and Group B (this package). Register touches no keystore and no
// network — building the server is safe for `daxie mcp tools` introspection. svc
// may be nil for pure schema-introspection callers (registration binds svc into the
// handler closures but does not invoke it).
func Register(srv *mcp.Server, svc *service.Service) {
	// ── 1–4: read/list (no signing, no policy) ──────────────────────────────
	addRead(srv, "balance", descBalance, svc.Balance)
	addReadPlain(srv, "token_list", descTokenList, svc.TokenList)
	addRead(srv, "token_info", descTokenInfo, svc.TokenInfo)
	addRead(srv, "nft_list", descNFTList, svc.NFTList)

	// ── 5: send (SIGNS; the §6.4 central guarantee) ─────────────────────────
	addWrite(srv, "send", descSend, sendCeremony, svc.SendTx)

	// ── 6: tx_status (read; the explicit poll primitive — never broadcasts) ──
	addTxResultRead(srv, "tx_status", descTxStatus, svc.TxStatus)
	// ── 7: tx_wait (long-poll; progress + dual-signal timeout) ──────────────
	addTxResultRead(srv, "tx_wait", descTxWait, svc.WaitTx)
	// ── 8: tx_list (read) ───────────────────────────────────────────────────
	addReadPlain(srv, "tx_list", descTxList, svc.ListTxs)
	// ── 9–10: RBF (SIGN) ────────────────────────────────────────────────────
	addWrite(srv, "tx_speedup", descTxSpeedup, speedupCeremony, svc.Speedup)
	addWrite(srv, "tx_cancel", descTxCancel, cancelCeremony, svc.Cancel)
	// ── 11: receive (long-poll; listening-address-first progress) ───────────
	addReceive(srv, "receive", descReceive, svc.Receive)

	// ── 12–13: approvals (SIGN; spend-equivalents) ──────────────────────────
	addWrite(srv, "token_approve", descTokenApprove, approveCeremony, svc.TokenApprove)
	addWrite(srv, "token_revoke", descTokenRevoke, revokeCeremony, svc.TokenRevoke)
	// ── 14: allowance (read) ────────────────────────────────────────────────
	addRead(srv, "token_allowance", descTokenAllowance, svc.TokenAllowance)

	// ── 15–16: off-chain signing (SIGN; no EventSink, no Confirm field) ─────
	addSign(srv, "sign_message", descSignMessage, svc.SignMessage)
	addSign(srv, "sign_typed_data", descSignTyped, svc.SignTyped)
	// ── 17: verify (read; pure ecrecover + endpoint echo) ───────────────────
	addReadPlain(srv, "verify", descVerify, svc.Verify)

	// ── 18–21: keystore-grouping metadata (read; never a secret) ────────────
	addReadPlain(srv, "wallet_list", descWalletList, svc.WalletList)
	addReadPlain(srv, "wallet_show", descWalletShow, svc.WalletShow)
	addReadPlain(srv, "accounts_list", descAccountsList, svc.AccountList)
	addReadPlain(srv, "account_show", descAccountShow, svc.AccountShow)

	// ── 22: gas (read) ──────────────────────────────────────────────────────
	addRead(srv, "gas", descGas, svc.Gas)
	// ── 23: convert (PURE; no chain/keystore/policy/Principal) ──────────────
	addConvert(srv, "convert", descConvert, svc.Convert)
	// ── 24–25: ENS (read) ───────────────────────────────────────────────────
	addRead(srv, "ens_resolve", descEnsResolve, svc.EnsResolve)
	addRead(srv, "ens_reverse", descEnsReverse, svc.EnsReverse)
	// ── 26: policy_show (read; READ-ONLY — the one policy verb on the surface)
	addPolicyShow(srv, "policy_show", descPolicyShow, svc.PolicyShow)

	// ── 27–28: contract read (eth_call / eth_getLogs; NEVER signs) ──────────
	addReadPlain(srv, "contract_call", descContractCall, svc.ContractCall)
	addReadPlain(srv, "contract_logs", descContractLogs, svc.ContractLogs)
	// ── 29–30: contract pure (no chain, no signing, no policy) ──────────────
	addReadPlain(srv, "contract_encode", descContractEncode, svc.EncodeCalldata)
	addReadPlain(srv, "contract_decode", descContractDecode, svc.DecodeCalldata)
	// ── 31: contract_send (SIGNS; selector-classifier bound to the ceremonies)
	addWrite(srv, "contract_send", descContractSend, contractSendCeremony, svc.ContractSend)
}

// ToolNames is the canonical roster of the 31 §6.1 tools, in table order. It is the
// tested artifact the golden/count test diffs against the actually-registered set:
// Register MUST register exactly these names, no more, no fewer.
var ToolNames = []string{
	"balance",         // 1
	"token_list",      // 2
	"token_info",      // 3
	"nft_list",        // 4
	"send",            // 5  SIGN
	"tx_status",       // 6
	"tx_wait",         // 7  long-poll
	"tx_list",         // 8
	"tx_speedup",      // 9  SIGN
	"tx_cancel",       // 10 SIGN
	"receive",         // 11 long-poll
	"token_approve",   // 12 SIGN
	"token_revoke",    // 13 SIGN
	"token_allowance", // 14
	"sign_message",    // 15 SIGN
	"sign_typed_data", // 16 SIGN
	"verify",          // 17
	"wallet_list",     // 18
	"wallet_show",     // 19
	"accounts_list",   // 20
	"account_show",    // 21
	"gas",             // 22
	"convert",         // 23 PURE
	"ens_resolve",     // 24
	"ens_reverse",     // 25
	"policy_show",     // 26 read-only
	"contract_call",   // 27
	"contract_logs",   // 28
	"contract_encode", // 29 PURE
	"contract_decode", // 30 PURE
	"contract_send",   // 31 SIGN
}

// SigningTools is the canonical set of the 8 signing tools (§6.1/§6.7 footer: "8
// signing"). Every one routes through the SAME service method that holds the only
// path to domain.Signer, with policy.Reserve + checks INSIDE it (§6.4) — so MCP is
// policy-gated identically to the CLI. receive derives an address but never signs;
// it is NOT in this set (it is counted read-only). The remaining 23 tools are
// read-only/pure. 8 + 23 = 31.
var SigningTools = []string{
	"send",
	"tx_speedup",
	"tx_cancel",
	"token_approve",
	"token_revoke",
	"sign_message",
	"sign_typed_data",
	"contract_send",
}

// ExcludedTools is the recorded, non-regressable deliberately-NOT-tools boundary
// (§6.1): a representative denylist of operation names that MUST NEVER be registered
// as MCP tools in v1. The boundary is enforced by ABSENCE — there is no handler for
// any of these — and this list makes the boundary a TESTED artifact: Group C's
// server_test asserts the registered tool set is DISJOINT from this set, so a future
// edit that adds (say) a wallet_export tool fails the build.
//
// The one sentence (§6.1): the MCP surface can move funds WITHIN policy and read
// everything, but it cannot change who holds the keys, change what the keys may do,
// change what an alias means, or read a key out. Every name below is one of those
// forbidden capabilities. policy_show (read-only) is the ONE policy verb that IS
// exposed — it is NOT in this list.
var ExcludedTools = []string{
	// All policy MUTATIONS — admin-passphrase-gated, the agent never holds it.
	"policy_set",
	"policy_allow",
	"policy_deny",
	"policy_reset",
	"policy_change_admin_passphrase",
	"policy_typed_allow",
	"policy_typed_remove",
	"policy_contract_allow",
	"policy_contract_remove",
	// Key EXPORT — no key exfiltration through the tool channel, ever, in v1.
	"wallet_export",
	"account_export",
	// Key/wallet CREATE & IMPORT — secret-emitting / attacker-key-planting ops.
	"wallet_create",
	"wallet_import",
	"account_import",
	// Account derive/alias/use — keystore-index/default-pointer mutations. The
	// fresh invoice address an agent needs is delivered by receive's new:true.
	"account_derive",
	"account_alias",
	"account_unalias",
	"account_use",
	// Keystore passphrase rotation — administration is CLI-only.
	"keystore_change_passphrase",
	// Network / rpc MUTATIONS (and rpc test, a debugging affordance, not exposed).
	"network_add",
	"network_use",
	"network_remove",
	"rpc_add",
	"rpc_use",
	"rpc_rename",
	"rpc_remove",
	"rpc_test",
	// Destruction — an operator act.
	"wallet_delete",
	"account_delete",
	"token_remove",
	"token_rename",
	"nft_remove",
	"contacts_remove",
	"contract_remove",
	// Registry *_add — alias/ABI spoofing primitives (a redefined alias changes
	// what an alias means for every later send/contract_send).
	"token_add",
	"nft_add",
	"contacts_add",
	"contract_add",
	// Contract registry introspection — the agent transacts by raw 0x + inline ABI
	// and never needs the operator-curated alias map (a mild recon affordance).
	"contract_list",
	"contract_show",
	// Self-referential / shell-only.
	"mcp_serve",
	"mcp_tools",
	"version",
	"completion",
	"config",
}

// ─── the read/list handler wrappers (§6.2; no signing, no policy) ────────────
//
// These bind args → the SAME domain request → the SAME service method → result.
// They contain NO business logic; the only difference between them is the SHAPE of
// the service method (some read methods take an EventSink, some do not — the §0.1
// D3 deviation), so there is one wrapper per shape and the Register list above
// picks the right one. The Out is returned as a pointer so the SDK's typed-nil
// handling marshals a real object even on an (impossible) empty path.

// readSinkFn is a read/metadata service method that takes an EventSink (Balance/
// TokenInfo/NFTList/TokenAllowance/Gas/EnsResolve/EnsReverse). The sink is wired (a
// read may emit a `resolved` echo) but a read never blocks on it.
type readSinkFn[In, Out any] func(context.Context, domain.Principal, In, domain.EventSink) (Out, error)

func addRead[In, Out any](srv *mcp.Server, name, desc string, fn readSinkFn[In, Out]) {
	mcp.AddTool(srv, withSchemas[In, Out](readToolDef(name, desc)),
		func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *Out, error) {
			out, err := fn(ctx, domain.LocalMCP(), in, progressSink(ctx, req))
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// readPlainFn is a read/metadata or pure service method that takes (ctx, Principal,
// In) with NO EventSink (TokenList/ListTxs/Verify/WalletList/WalletShow/AccountList/
// AccountShow/ContractCall/ContractLogs/EncodeCalldata/DecodeCalldata).
type readPlainFn[In, Out any] func(context.Context, domain.Principal, In) (Out, error)

func addReadPlain[In, Out any](srv *mcp.Server, name, desc string, fn readPlainFn[In, Out]) {
	mcp.AddTool(srv, withSchemas[In, Out](readToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *Out, error) {
			out, err := fn(ctx, domain.LocalMCP(), in)
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// txResultReadFn is a NON-signing service method with the signing-method SHAPE —
// (ctx, Principal, In, EventSink) → (TxResult, error). tx_status folds the journal
// record + one receipt re-check (never broadcasts); tx_wait runs the §5.3 wait
// machine on a known hash (it streams progress but signs nothing). Both surface the
// dual-signal tx codes (a status/wait can report tx.reverted on a mined-reverted
// hash, or tx.wait_timeout / status:"pending" at the deadline) so an agent reads
// BOTH the error code AND the TxResult (§6.6). There is no signing ceremony (no
// Confirm/Wait mutation) — these are read-class tools.
type txResultReadFn[In any] func(context.Context, domain.Principal, In, domain.EventSink) (domain.TxResult, error)

func addTxResultRead[In any](srv *mcp.Server, name, desc string, fn txResultReadFn[In]) {
	mcp.AddTool(srv, withSchemas[In, domain.TxResult](readToolDef(name, desc)),
		func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *domain.TxResult, error) {
			out, err := fn(ctx, domain.LocalMCP(), in, progressSink(ctx, req))
			if dualSignal(err) {
				return dualResult(err), &out, nil // BOTH IsError + structured Out (§6.6)
			}
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}
