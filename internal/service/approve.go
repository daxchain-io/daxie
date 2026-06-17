package service

import (
	"context"
	"math/big"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/erc"
	"github.com/daxchain-io/daxie/internal/ethunit"
	"github.com/daxchain-io/daxie/internal/journal"
)

// approve.go is the M5 ERC-20 approval surface (design §4.2, §5.1, cli-spec
// §`daxie token approve`/`revoke`). An approval is a SPEND-EQUIVALENT: it runs
// through the SAME §2.7 authorize→broadcast→settle/abort kernel as a transfer
// (runSend), with kind=KindApprove. The non-negotiables (review hunts these):
//
//   - The policy DESTINATION for an approval is the SPENDER (decoded from the
//     calldata), NEVER the token contract (§4.2). Intent.policyDest carries it.
//   - The allowlist (stage 3 on the spender) + the fail-closed-no-allowlist rule
//     (stage 3c) + the --unlimited --yes ceremony (stage 6) ALL run through the
//     REAL M4 engine UNCHANGED — M5 only builds the Check correctly.
//   - Unlimited is approve(spender, 2^256-1); it requires the explicit
//     --unlimited --yes acknowledgement (Check.Acked). Without it the engine
//     returns policy.denied.unlimited_unacked (exit 3).
//   - SpendWei stays 0 (no ETH/price oracle); the token amount is display-only.
//     Decimals are read once for display; the amount crosses as base units.
//   - Revoke is approve(spender, 0) — the same path with amount forced to zero.

// TokenApprove builds and broadcasts an ERC-20 approve(spender, amount) through the
// authorize kernel as a KindApprove spend-equivalent (`daxie token approve`).
func (s *Service) TokenApprove(ctx context.Context, p domain.Principal, req domain.ApproveRequest, sink domain.EventSink) (domain.TxResult, error) {
	return s.runApprove(ctx, p, req, false, sink)
}

// TokenRevoke is sugar for approve(spender, 0): it sets the allowance to zero,
// the same KindApprove path with amount forced to zero (`daxie token revoke`).
func (s *Service) TokenRevoke(ctx context.Context, p domain.Principal, req domain.ApproveRequest, sink domain.EventSink) (domain.TxResult, error) {
	return s.runApprove(ctx, p, req, true, sink)
}

// runApprove is the shared approve/revoke body. revoke forces amount=0; an
// --unlimited request encodes the 2^256-1 sentinel and requires Confirm (the
// --yes ack). It resolves the asset + the spender, builds the approve calldata,
// and hands an Intent to runSend (the same kernel tx send uses).
func (s *Service) runApprove(ctx context.Context, p domain.Principal, req domain.ApproveRequest, revoke bool, sink domain.EventSink) (domain.TxResult, error) {
	in, amount, err := s.resolveApproveIntent(ctx, p, req, revoke, sink)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer in.cc.Close()

	// Preview the gas quote BEFORE the lock (§5.1), exactly like a send. The approve
	// calldata is non-empty so estimateGas reflects the real cost (never the 21000
	// EOA exception).
	if err := s.previewGas(ctx, &in, gasReqFromApprove(req), sink); err != nil {
		return domain.TxResult{}, err
	}

	// --dry-run: the check-only policy verdict (no reservation), then stop before sign.
	if req.DryRun {
		return s.dryRun(ctx, &in)
	}

	unlocker, zero, err := s.withUnlocker(false)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer zero()
	in.unlocker = unlocker

	res, rerr := s.runSend(ctx, p, &in, req.Wait, sink)
	_ = amount // amount is carried in the asset block + the Check (built in authorize)
	return res, rerr
}

// resolveApproveIntent builds the prefetch-stage Intent for an approval (§2.7): it
// resolves From (the signing ref), the SPENDER (the policy subject, via 0x/contact),
// the asset (registry-only alias resolution), dials the endpoint, computes the
// amount (revoke→0, --unlimited→2^256-1, else --amount in base units), and builds
// the approve calldata. The tx `to` is the TOKEN CONTRACT; the policy dest is the
// SPENDER.
func (s *Service) resolveApproveIntent(ctx context.Context, p domain.Principal, req domain.ApproveRequest, revoke bool, sink domain.EventSink) (Intent, *big.Int, error) {
	// ── From: the signing ref (flag>env>meta.json default) ──
	fromStr := req.From
	if fromStr == "" {
		fromStr = s.activeDefault(ctx)
	}
	if fromStr == "" {
		return Intent{}, nil, domain.New(domain.CodeUsage+".no_account",
			"no --from given and no default account set (run `daxie account use`)")
	}
	fromRef, err := domain.ParseAccountRef(fromStr)
	if err != nil {
		return Intent{}, nil, err
	}
	from, err := s.keys.AddressOf(fromRef)
	if err != nil {
		return Intent{}, nil, err
	}

	// ── spender: the POLICY subject (0x literal or contact name) ──
	spenderDest, err := s.resolveDest(ctx, ChainRequest{Network: req.Network, RPC: req.RPC}, req.Spender)
	if err != nil {
		return Intent{}, nil, err
	}
	emitResolvedDest(sink, "spender ", spenderDest)

	// ── dial + chain id ──
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return Intent{}, nil, err
	}
	network := s.networkName(req.Network)
	chainID, err := cc.ChainID(ctx)
	if err != nil {
		cc.Close()
		return Intent{}, nil, mapRPCErr(err)
	}

	// ── asset (registry-only alias resolution; raw 0x reads decimals on-chain) ──
	ra, err := s.resolveAsset(ctx, cc, network, req.Token)
	if err != nil {
		cc.Close()
		return Intent{}, nil, err
	}

	// ── amount: revoke→0, --unlimited→2^256-1, else --amount in base units ──
	amount, unlimited, err := approveAmount(req, revoke, ra.decimals)
	if err != nil {
		cc.Close()
		return Intent{}, nil, err
	}

	// ── the approve calldata: selector 0x095ea7b3 || abi(spender, amount) ──
	data := s.erc.ApproveCalldata(spenderDest.Address, amount)

	decInt := int(ra.decimals)
	amtStr := amount.String()
	contractHex := strings.ToLower(ra.contract.Hex())
	in := Intent{
		chainID: chainID,
		network: network,
		rpc:     req.RPC,
		cc:      cc,
		from:    from,
		ref:     fromRef,
		// dest is the SPENDER for the result echo + the policy subject (policyDest).
		dest:       spenderDest,
		to:         ra.contract,         // the tx goes TO the token contract
		value:      big.NewInt(0),       // an approval carries no ETH
		data:       data,                // approve calldata
		policyDest: spenderDest.Address, // THE policy subject = the spender (§4.2)
		policyKind: policyKindApprove,   // routes the Check to KindApprove
		tokenAmt:   new(big.Int).Set(amount),
		unlimited:  unlimited,
		acked:      req.Confirm, // the --unlimited --yes ceremony bit (also the bounded-confirm skip)
		kind:       journal.KindApprove,
		asset: journal.Asset{
			Kind:     "erc20",
			Contract: &contractHex,
			Alias:    ra.alias,
			Decimals: &decInt,
			Amount:   &amtStr,
		},
		source: sourceOf(p),
	}
	return in, amount, nil
}

// approveAmount computes the approval amount + the unlimited flag from the request:
//   - revoke ⇒ 0 (the revoke encoding), never unlimited;
//   - --unlimited ⇒ 2^256-1 (the sentinel the policy ceremony matches), and
//     --amount is rejected alongside it (an unlimited approval has no bounded
//     amount; the cli also guards this);
//   - else --amount parsed in the token's base units (no float).
//
// The unlimited flag is NOT just the --unlimited toggle: a bounded --amount whose
// parsed base-unit value lands on any §4.2 unlimited sentinel (2^256-1, uint160
// max, uint96 max) IS an unbounded approval and MUST drive Check.Unlimited so the
// same `--unlimited --yes` ceremony fires (design §4.2 lines 1633/1644 — the
// ceremony fires on an unlimited approval "exactly as on the typed path",
// regardless of how it was specified). Otherwise `token approve <tok> --amount
// <2^256-1>` on a 0-decimal token would encode the exact infinite-allowance
// sentinel while bypassing the gate. erc.IsUnlimitedAmount is the SINGLE match set
// the calldata builder and the ceremony share.
func approveAmount(req domain.ApproveRequest, revoke bool, decimals uint8) (*big.Int, bool, error) {
	if revoke {
		return big.NewInt(0), false, nil
	}
	if req.Unlimited {
		if strings.TrimSpace(req.Amount) != "" {
			return nil, false, domain.New(domain.CodeUsage+".bad_amount",
				"--unlimited and --amount are mutually exclusive")
		}
		return erc.MaxUint256(), true, nil
	}
	if strings.TrimSpace(req.Amount) == "" {
		return nil, false, domain.New(domain.CodeUsage+".missing_amount",
			"--amount is required (or use --unlimited)")
	}
	amt, err := ethunit.ParseTokenAmount(strings.TrimSpace(req.Amount), decimals)
	if err != nil {
		return nil, false, domain.Wrap(domain.CodeUsage+".bad_amount", "invalid --amount "+req.Amount, err)
	}
	// A bounded --amount that lands on a §4.2 unlimited sentinel is an unbounded
	// approval: flag it so it takes the ceremony exactly like the --unlimited path.
	return amt, erc.IsUnlimitedAmount(amt), nil
}

// gasReqFromApprove projects an ApproveRequest's network/endpoint into the
// TxRequest shape previewGas/buildGas consume (they read only Network/RPC/gas
// fields; an approval takes no explicit gas overrides in v1 — gas is estimated).
func gasReqFromApprove(req domain.ApproveRequest) domain.TxRequest {
	return domain.TxRequest{Network: req.Network, RPC: req.RPC}
}

// sourceOf attributes the source (cli|mcp) from the Principal (§5.6).
func sourceOf(p domain.Principal) string {
	if p.Label == "mcp" {
		return "mcp"
	}
	return "cli"
}
