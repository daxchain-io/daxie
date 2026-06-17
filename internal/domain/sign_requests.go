package domain

// sign_requests.go is the M9 `daxie sign` / `daxie verify` wire contract (design
// §2.7, §4.2, §4.3 stage 5; cli-spec §`daxie sign`/§`daxie verify`). It carries the
// request/result shapes for off-chain message signing (EIP-191 personal_sign) and
// typed-data signing (EIP-712), plus the verify (ecrecover) round-trip. It is
// triple-duty (CLI flags, the future MCP input/output schema, and the in-process
// service call) and holds NO float (§2.5): every signature, digest, and address is
// a 0x-hex string assembled by the core.
//
// The signing core itself lives in internal/service/sign.go + verify.go; this file
// is only the boundary types both frontends bind against. The non-negotiables the
// types encode (review hunts these):
//   - EIP-191 ALWAYS wraps the \x19Ethereum Signed Message:\n<len> prefix — over the
//     raw bytes OR the 32-byte --no-hash digest; raw unprefixed eth_sign is NEVER
//     offered (§4.2 row 2). The frontend decodes --no-hash to 32 raw bytes; the core
//     applies the prefix uniformly so "prefix always applied" lives in one place.
//   - EIP-712 routes through the §2.7 authorizeSignature gate BEFORE the key is
//     touched (a recognized permit is policy-checked at SIGNATURE time exactly like an
//     on-chain approval; an unrecognized message hits the §4.3 stage-5 typed gate).
//   - verify recovers the signer via ecrecover and asserts it equals the claimed
//     --address (resolved when an ENS name, §10.2).

// SignMessageRequest is `daxie sign message` (EIP-191 personal_sign). Account is the
// signing ref ("treasury/0", "ops-key"; flag>env>default, resolved by the frontend
// before the call). Message is the raw message bytes; when NoHash is true Message is
// the 32-byte pre-hashed digest (cli-spec `--no-hash`) over which the EIP-191 prefix
// is STILL applied (raw eth_sign is never offered, §4.2). Network/RPC select the
// endpoint only for the unified result echo + the `messages` kill-switch read; EIP-191
// needs no chainId (there is no chainId in the prefix).
type SignMessageRequest struct {
	Account string
	Message []byte // raw message bytes, OR the 32-byte digest when NoHash
	NoHash  bool
	Network string
	RPC     string
}

// SignTypedRequest is `daxie sign typed` (EIP-712). Typed is the raw JSON bytes of an
// apitypes.TypedData document (from --data <file> or --data-stdin). Account is the
// signer. The active network's chainId is fetched by the core to drive the §4.2
// chain-mismatch deny (a permit for chain 1 signed "while on Sepolia").
type SignTypedRequest struct {
	Account string
	Typed   []byte // raw EIP-712 JSON
	Network string
	RPC     string
	// Acked is the --unlimited --yes ceremony bit for a recognized UNLIMITED permit
	// (mirrors ApproveRequest.Confirm). Without it an unlimited permit is refused with
	// policy.denied.unlimited_unacked (§4.3 stage 6).
	Acked bool
}

// VerifyRequest is `daxie verify`. Exactly one of Message/Typed is set. Signature is
// the 0x 65-byte [R||S||V] hex. Address is the claimed signer as a 0x literal OR an
// ENS name (resolved, then compared, §10.2). NoHash applies to the Message path (the
// message is a pre-hashed 32-byte digest, the EIP-191 prefix is still applied).
type VerifyRequest struct {
	Message   []byte // EIP-191 path (raw bytes, or the 32-byte digest when NoHash)
	Typed     []byte // EIP-712 path (raw JSON)
	NoHash    bool
	Signature string // 0x… 65-byte
	Address   string // 0x… or name.eth
	Network   string
	RPC       string
}

// SigResult is the sign output: the 65-byte signature, the signer address, the digest
// that was actually signed (for audit), and the scheme. The signature carries V in
// {27,28} for wallet interop; verify normalizes it back before ecrecover.
type SigResult struct {
	Signature string `json:"signature"` // 0x… 65-byte [R||S||V] (V in {27,28})
	Signer    string `json:"signer"`    // 0x… checksummed
	Digest    string `json:"digest"`    // 0x… the 32-byte hash signed (EIP-191 or EIP-712)
	Scheme    string `json:"scheme"`    // "eip191" | "eip712"
}

// VerifyResult is the verify output: whether the recovered address equals the claimed
// signer, plus the recovered address for the mismatch case. A mismatch returns this
// populated result alongside the CodeVerifyMismatch error so the agent reads BOTH the
// claimed and the recovered address.
type VerifyResult struct {
	Valid     bool   `json:"valid"`
	Signer    string `json:"signer"`    // the claimed address (resolved if ENS)
	Recovered string `json:"recovered"` // the ecrecover result
	Digest    string `json:"digest"`
	Scheme    string `json:"scheme"` // "eip191" | "eip712"
}

// The M9 sign/verify error codes (§5.7 exit registry). All four are input/validation
// outcomes mapped to exit 2 (ExitUsage) in domain.codeExit:
//   - CodeSignBadMessage / CodeSignBadTyped — malformed message / typed-data input.
//   - CodeVerifyBadSig — a malformed 0x 65-byte signature.
//   - CodeVerifyMismatch — a well-formed request whose recovered address does NOT
//     equal the claim. Deliberately exit 2 (validation), NEVER exit 4 (auth): exit 4
//     is reserved for a wrong/missing keystore passphrase, and an agent must not
//     confuse "your passphrase is wrong" with "this signature doesn't verify".
//
// The keystore-passphrase-required failure on the SIGNING side already maps via the
// existing keystore.bad_passphrase → ExitAuth (4) seam; SignMessage/SignTyped inherit
// it for free from the domain.Signer/Unlocker boundary.
const (
	CodeSignBadMessage = "sign.bad_message"
	CodeSignBadTyped   = "sign.bad_typed"
	CodeVerifyBadSig   = "verify.bad_signature"
	CodeVerifyMismatch = "verify.mismatch"
)
