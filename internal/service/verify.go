package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// verify.go is the M9 ecrecover round-trip (`daxie verify`, design §2.7; cli-spec
// §`daxie verify`). It recovers the signer from a signature over the reconstructed
// digest and asserts it equals the claimed --address (resolved when an ENS name,
// §10.2). It reconstructs the SAME digest the signing core produced: the EIP-191
// \x19 prefix digest (Message path) or the apitypes.TypedDataAndHash digest (Typed
// path).
//
// Correctness invariants (review hunts these):
//   - ecrecover is used correctly: the recovered address MUST equal the claimed
//     signer for valid==true. A tampered signature/message recovers a DIFFERENT (or
//     no) address → valid:false + verify.mismatch (exit 2, a validation outcome,
//     never exit 4).
//   - geth's SigToPub expects V ∈ {0,1} in byte 64 while wallets emit {27,28};
//     parseSig65 normalizes it back so a wallet-format signature verifies.
//   - --address accepts a 0x literal OR an ENS name (resolved, then compared); the
//     resolved address is echoed in VerifyResult.Signer.

// Verify recovers the signer from req.Signature over the reconstructed digest and
// reports whether it equals the claimed address. A mismatch returns the POPULATED
// result alongside CodeVerifyMismatch so the agent reads both the claimed and the
// recovered address; a malformed signature is CodeVerifyBadSig (exit 2).
func (s *Service) Verify(ctx context.Context, _ domain.Principal, req domain.VerifyRequest) (domain.VerifyResult, error) {
	sig, err := parseSig65(req.Signature)
	if err != nil {
		return domain.VerifyResult{}, err
	}

	digest, scheme, derr := s.verifyDigest(&req)
	if derr != nil {
		return domain.VerifyResult{}, derr
	}

	pub, perr := gethcrypto.SigToPub(digest.Bytes(), sig)
	if perr != nil {
		return domain.VerifyResult{}, domain.Wrap(domain.CodeVerifyBadSig,
			"the signature is malformed (cannot recover a public key)", perr)
	}
	recovered := gethcrypto.PubkeyToAddress(*pub)

	claimed, cerr := s.resolveClaimedAddress(ctx, req)
	if cerr != nil {
		return domain.VerifyResult{}, cerr
	}

	res := domain.VerifyResult{
		Valid:     recovered == claimed,
		Signer:    claimed.Hex(),
		Recovered: recovered.Hex(),
		Digest:    digest.Hex(),
		Scheme:    scheme,
	}
	if !res.Valid {
		return res, domain.Newf(domain.CodeVerifyMismatch,
			"the signature recovers to %s, not the claimed %s", recovered.Hex(), claimed.Hex())
	}
	return res, nil
}

// verifyDigest reconstructs the digest the signature is checked against: the EIP-712
// digest (Typed path) or the EIP-191 prefix digest (Message path, default). The
// EIP-191 prefix is ALWAYS applied — over the raw bytes OR the 32-byte --no-hash
// digest the frontend decoded — matching the signing side exactly.
func (s *Service) verifyDigest(req *domain.VerifyRequest) (common.Hash, string, error) {
	if req.Typed != nil {
		var td apitypes.TypedData
		if err := json.Unmarshal(req.Typed, &td); err != nil {
			return common.Hash{}, "", domain.Wrap(domain.CodeSignBadTyped,
				"the EIP-712 document is not valid JSON", err)
		}
		digest, herr := eip712Digest(&td)
		if herr != nil {
			return common.Hash{}, "", domain.Wrap(domain.CodeSignBadTyped,
				"cannot hash the EIP-712 document", herr)
		}
		return digest, "eip712", nil
	}
	return eip191Digest(req.Message), "eip191", nil
}

// resolveClaimedAddress resolves the claimed --address: a 0x literal is used as-is; an
// ENS name is resolved through the per-request endpoint binding (the resolved address
// is echoed in VerifyResult.Signer). An empty address is verify.bad_signature usage
// (there is nothing to compare against).
func (s *Service) resolveClaimedAddress(ctx context.Context, req domain.VerifyRequest) (common.Address, error) {
	addr := strings.TrimSpace(req.Address)
	if addr == "" {
		return common.Address{}, domain.New(domain.CodeVerifyBadSig,
			"--address is required (the claimed signer, a 0x address or an ENS name)")
	}
	if common.IsHexAddress(addr) {
		return common.HexToAddress(addr), nil
	}
	// An ENS name → resolve through the connected network (the same fresh per-request
	// resolution the send path uses), then compare the recovered address to it.
	return s.resolveENSForPin(ctx, addr)
}

// parseSig65 decodes a 0x 65-byte [R||S||V] signature and normalizes V for ecrecover:
// geth's SigToPub expects V ∈ {0,1} in byte 64, while wallets (and our SigResult)
// emit {27,28}. A non-65-byte or non-hex input is verify.bad_signature (exit 2).
func parseSig65(s string) ([]byte, error) {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "0x") && !strings.HasPrefix(t, "0X") {
		return nil, domain.New(domain.CodeVerifyBadSig,
			"--signature must be a 0x-prefixed 65-byte hex signature")
	}
	b, err := hex.DecodeString(t[2:])
	if err != nil {
		return nil, domain.Wrap(domain.CodeVerifyBadSig, "--signature is not valid hex", err)
	}
	if len(b) != 65 {
		return nil, domain.Newf(domain.CodeVerifyBadSig,
			"--signature must be exactly 65 bytes ([R||S||V]), got %d", len(b))
	}
	// Normalize V {27,28} → {0,1} for SigToPub. A value already in {0,1} is left as-is.
	if b[64] >= 27 {
		b[64] -= 27
	}
	return b, nil
}
