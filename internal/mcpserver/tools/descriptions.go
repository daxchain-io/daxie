package tools

// descriptions.go holds the agent-facing tool descriptions (design §6.3) — written
// for a model DECIDING WHICH TOOL TO CALL, not for a human reading docs. They are
// the human-authored half of the §6.7 golden test (the schemas are inferred; the
// descriptions are pinned), so a description change is a reviewed diff.
//
// Three descriptions are §6.3 VERBATIM because they carry load-bearing safety
// guarantees a model must read before it acts:
//   - send / token_approve carry the spend-equivalent + policy-checked guarantee.
//   - contract_send carries the selector-classifier guarantee (raw calldata is NOT
//     a policy bypass — a known approve/transfer/permit is routed through the SAME
//     checks as token_approve, including the unlimited ceremony).
// The rest are authored to the same contract conventions (§6.2): amounts are
// decimal strings (never numbers — 10^18 is unrepresentable in IEEE-754, so the
// convert tool exists for unit math); to/spender/owner/account accept address |
// contact | ENS; from is optional everywhere (the default account); network/rpc are
// optional (empty = config defaults).

// ── 1–4: read/list ──────────────────────────────────────────────────────────

const descBalance = "Read an account's balance on a network. Returns the native (ETH) balance by default; set 'token' (alias or 0x) for one ERC-20 balance, or 'all':true for every registry token the account holds. 'account' accepts an account ref, a raw 0x address, or an ENS name; omit to use the default account. Read-only."

const descTokenList = "List the known ERC-20 tokens for a network — the bundled majors plus any locally-registered aliases. Use this to discover the alias/contract/decimals for a token before a balance, transfer, or approval. Read-only."

const descTokenInfo = "Read on-chain ERC-20 metadata (symbol, decimals, kind) for a token by alias or 0x contract, without registering it. Reports whether the address is in the local registry. Read-only."

const descNFTList = "List the NFTs an account owns across the locally-registered collections on a network (v1 enumerates the registry, not arbitrary on-chain holdings). 'account' is an account ref, 0x, or ENS; omit for the default account. Read-only."

// ── 5: send (§6.3 VERBATIM) ──────────────────────────────────────────────────

const descSend = "Sign and broadcast a transfer. Policy-checked before signing (spend limits, destination allowlist, gas cap). Waits for confirmations by default over MCP."

// ── 6–11: tx lifecycle + receive ─────────────────────────────────────────────

const descTxStatus = "Look up the current status of a transaction by hash: pending, confirmed, reverted, or replaced. Folds the local journal record with a single live receipt check; never broadcasts. A mined-but-reverted tx is reported as a tool error (code tx.reverted) AND the structured result, so you can read both. Read-only."

const descTxWait = "Block until a transaction reaches its confirmation target, streaming progress. 'confirmations' overrides the per-network default depth; 'timeout' (Go duration, e.g. '5m', default 10m) bounds the wait. At the deadline it returns status:'pending' as a tool error (code tx.wait_timeout) plus the structured result — re-call to resume. Use this to resume after a send timed out. Read-only (it waits on an existing tx; it never signs)."

const descTxList = "List this wallet's recent transactions from the local journal, newest first. Filter by 'account' and cap with 'limit'. The journal is the history (terminal rows are kept). Read-only."

const descTxSpeedup = "Replace a pending, Daxie-originated transaction with a higher-fee copy (RBF) to get it mined faster. Identify it by 'hash'. The bumped fees are re-checked against the policy gas cap. A foreign or already-mined hash is an error. Waits for confirmations by default over MCP."

const descTxCancel = "Replace a pending, Daxie-originated transaction with a 0-value self-send at higher fees to cancel it (RBF). Identify it by 'hash'. Re-checked against the policy gas cap; an already-mined hash is an error. Waits for confirmations by default over MCP."

const descReceive = "Watch a receiving address for an inbound transfer and block until it confirms, streaming progress. The receiving address is emitted as the FIRST progress notification (give it to the counterparty). Omit 'amount' to accept any inbound ETH; set 'amount' for a target, 'token'/'nft' for a non-ETH asset, 'exact':true to require one single matching transfer. 'new':true derives a FRESH invoice address (requires a writable keystore and 'wallet'). IMPORTANT: by default this blocks FOREVER — set 'timeout' (e.g. '30m') so the call is bounded; on timeout it returns a resumable result, not an error. Read-only (it derives/echoes an address but never signs)."

// ── 12–14: approvals + allowance ─────────────────────────────────────────────

// descTokenApprove is §6.3 VERBATIM (the spend-equivalent guarantee).
const descTokenApprove = "Approve an ERC-20 spender. APPROVALS ARE SPEND-EQUIVALENTS: policy-checked like a transfer (spender must pass the allowlist), and an unlimited approval grants the spender an unbounded allowance over every unit the account ever holds."

const descTokenRevoke = "Revoke an ERC-20 spender by setting its allowance to 0 (an approve(spender, 0)). Policy-checked and broadcast through the same signing pipeline as an approval. Use 'token' and 'spender'; 'amount' and 'unlimited' are ignored on the revoke path. Waits for confirmations by default over MCP."

const descTokenAllowance = "Read the current ERC-20 allowance a spender holds over an owner's balance. 'owner' defaults to the active account; 'spender' is required. Returns the exact base-unit allowance, a decimals-aware human form, and whether it is unlimited. Read-only."

// ── 15–17: off-chain signing + verify ────────────────────────────────────────

const descSignMessage = "Sign an off-chain message with an account's key (EIP-191 personal_sign). The Ethereum Signed Message prefix is ALWAYS applied (raw eth_sign is never offered). 'message' is the raw bytes (base64 over MCP); set 'noHash':true when 'message' is a pre-hashed 32-byte digest. Returns the signature, signer, and digest. Signs with a key; not a fund-moving op."

const descSignTyped = "Sign an EIP-712 typed-data document with an account's key. A recognized permit (EIP-2612 / DAI-style / Permit2) is policy-checked at SIGNATURE time EXACTLY like an on-chain approval — including the unlimited ceremony; unrecognized typed data is deny-by-default once a policy is active. 'typed' is the raw EIP-712 JSON (base64 over MCP); set 'acknowledge_unlimited':true to acknowledge a recognized UNLIMITED permit (otherwise it is refused). Returns the signature, signer, and digest."

const descVerify = "Verify a signature: recover the signer via ecrecover and check it equals the claimed 'address' (which may be a 0x literal or an ENS name). Provide exactly one of 'message' (EIP-191) or 'typed' (EIP-712), plus the 0x 65-byte 'signature'. A mismatch returns valid:false with the recovered address (a validation outcome, not an auth failure). Read-only."

// ── 18–21: keystore-grouping metadata (NEVER a secret) ───────────────────────

const descWalletList = "List the HD wallets in the keystore: names, ids, account counts, creation dates. Returns NON-SECRET grouping metadata only — never a mnemonic, key, or seed. Read-only."

const descWalletShow = "Show one HD wallet by name: its id, BIP-44 derivation path prefix, next index, and the derived accounts (refs, addresses, aliases). NON-SECRET metadata only — never a mnemonic or seed. Read-only."

const descAccountsList = "List signing accounts (HD and standalone) and the current default. Returns refs, addresses, kinds, wallet/index/alias — NON-SECRET metadata only, never a key. Filter with 'wallet'. Read-only."

const descAccountShow = "Show one account by ref: its address, kind, wallet/index, alias, and full BIP-44 path for an HD account. NON-SECRET metadata only — never a private key. Read-only."

// ── 22–25: gas, convert, ENS ─────────────────────────────────────────────────

const descGas = "Read current gas/fee quotes for a network at three speeds (slow/normal/fast) plus the next base fee. Use this to choose fee parameters before a send. Every fee is an exact wei decimal string. Read-only."

const descConvert = "Convert an amount between Ethereum units (wei, gwei, eth). Pure arithmetic — no network, no keystore. Pass 'amount' (with an optional unit suffix like '1.5eth', or set 'from') and the target 'to' unit. Use this whenever you need exact base-unit math instead of computing 10^18 yourself (which a float cannot represent)."

const descEnsResolve = "Forward-resolve an ENS name to its address on a network. Resolution is per-network (the same name resolves independently on mainnet vs Sepolia). Returns the checksummed address; an unresolved name is a clean error, never an all-zero address. Read-only."

const descEnsReverse = "Reverse-resolve an address to its primary ENS name on a network. The result is FORWARD-VERIFIED: a name is returned only when it forward-resolves back to the address (verified:true); otherwise name is empty and verified:false. Never trust an unverified reverse name. Read-only."

// ── 26: policy_show (the one policy verb, read-only) ──────────────────────────

const descPolicyShow = "Read the active signing policy: whether guardrails are on, the default and per-network spend limits, the destination/spender allowlist and denylist, and the self-address set. Use this to pre-flight whether a transfer is in-policy before you try it. READ-ONLY — there is no tool to change the policy (mutations are admin-passphrase-gated and operator-only). Read-only."

// ── 27–31: contract ──────────────────────────────────────────────────────────

const descContractCall = "Call a read-only (view/pure) contract method via eth_call. NEVER signs, NEVER policy-checked. 'contract' is a registry alias, raw 0x, or ENS; 'method' is the function name (or carried by 'abi.sig'); 'args' are positional strings coerced by the ABI; provide the ABI by alias, inline 'abi' JSON, or 'abi.sig'. Returns the decoded, labeled outputs. Read-only."

const descContractLogs = "Read decoded event logs for a contract via eth_getLogs. NEVER signs. 'contract' is an alias/0x/ENS; 'event' is the event name (or 'abi.sig'); 'args' filter on indexed args (name=value); 'fromBlock'/'toBlock' bound the range. Returns the decoded, labeled log args. Read-only."

const descContractEncode = "Build raw calldata: selector || abi(args) -> 0x bytes. Pure — for relayers, meta-transactions, and debugging; touches no chain, no keystore, no policy. Provide the function via 'method'+ABI or 'abi.sig', and 'args' as positional strings. Returns the 0x calldata."

const descContractDecode = "Decode 0x calldata into its method, 4-byte selector, and labeled arguments. Pure — never touches the chain or policy. Provide an ABI via alias, inline 'abi', or 'abi.sig' to label the args. Use this to inspect what a calldata blob does before sending it."

// descContractSend is §6.3 VERBATIM (the selector-classifier guarantee).
const descContractSend = "Sign and broadcast a state-changing call to ANY contract (the escape hatch for non-standard ABIs). Policy-checked before signing EXACTLY like 'send': the contract is the destination (allowlist), --value + gas count toward spend limits and the gas cap, and it FAILS CLOSED when limits are set but no allowlist is. CRITICAL: if the calldata encodes a known approve/transfer/permit, it is classified and routed through the SAME checks as token_approve — including the unlimited ceremony; raw calldata is NOT a policy bypass. Provide the ABI by registry alias, or pass abi/sig inline with a raw 0x address. Waits for confirmations by default over MCP."
