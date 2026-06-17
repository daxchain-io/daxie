package service

import (
	"context"
	"math/big"
	"strings"
	"testing"

	dabi "github.com/daxchain-io/daxie/internal/abi"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/ethereum/go-ethereum/common"
)

// contract_test.go covers the M10 `daxie contract` use cases at the unit level (with
// the fake chain): the §5.1 contract-send Intent mapping, the §4.2 classify-into-
// KindApprove crux (the IDENTICAL Check the typed path emits), the §4.3 stage-5b
// unknown-calldata flip, the §5.11 PURE encode/decode round-trip (no chain, no policy),
// and the contract registry CRUD. The integration test (contract_integration_test.go)
// exercises the real EVM end-to-end; these pin the wiring deterministically.

const erc20ABIJSON = `[{"type":"function","name":"approve","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"},{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"}]`

const stakingABIJSON = `[{"type":"function","name":"earned","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},{"type":"function","name":"stake","inputs":[{"name":"amount","type":"uint256"}],"outputs":[],"stateMutability":"nonpayable"}]`

// ── ContractSend Intent mapping (§5.1) ────────────────────────────────────────

func TestContractSend_IntentMapsCalldataAndValue(t *testing.T) {
	from := someAddr(0x01)
	contract := someAddr(0x42)
	svc, _, _ := sendService(t, from)

	// Register the staking contract so resolveABISource + resolveContractDest resolve
	// registry-only (no chain ABI read).
	addContract(t, svc, "stk", contract, stakingABIJSON)

	in, err := svc.resolveContractSendIntent(context.Background(), domain.LocalCLI(), domain.ContractSendRequest{
		Contract: "stk",
		Method:   "stake",
		Args:     []string{"5000"},
		Value:    "0.25", // msg.value → native value → SpendWei
		From:     from.Hex(),
		Network:  "mainnet",
	}, nil)
	if err != nil {
		t.Fatalf("resolveContractSendIntent: %v", err)
	}
	defer in.cc.Close()

	// The tx goes TO the contract; the policy destination is the contract (resolved+echoed).
	if in.to != contract {
		t.Errorf("intent.to = %s, want the contract %s", in.to.Hex(), contract.Hex())
	}
	if !in.isContractSend {
		t.Error("intent.isContractSend = false, want true (so authorize runs ClassifyCalldata)")
	}
	if in.kind != journal.KindContractCall {
		t.Errorf("intent.kind = %q, want contract-call", in.kind)
	}
	// data = stake selector 0xa694fc3a || abi(5000).
	if len(in.data) < 4 || strings.ToLower(common.Bytes2Hex(in.data[:4])) != "a694fc3a" {
		t.Fatalf("intent.data selector = %x, want a694fc3a (stake)", in.data[:4])
	}
	if got := new(big.Int).SetBytes(in.data[4:36]); got.Cmp(big.NewInt(5000)) != 0 {
		t.Errorf("intent.data amount = %s, want 5000", got)
	}
	// --value 0.25 ETH folds into the native value.
	want := new(big.Int).Mul(big.NewInt(25), new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil)) // 0.25e18
	if in.value.Cmp(want) != 0 {
		t.Errorf("intent.value = %s, want 0.25 ETH (%s)", in.value, want)
	}
}

// TestContractSend_IntentAckedFromUnlimitedNotConfirm pins the §4.2/§11-D12 fix: the
// Intent's acked bit (→ Check.Acked → the stage-6 unlimited gate) is sourced from the
// DELIBERATE --unlimited acknowledgement (req.AckUnlimited), NEVER from the bare --yes
// (req.Yes). A `contract send --yes` (Yes=true) carrying an unlimited approve must
// NOT be acked — only AckUnlimited=true acks it — so the generic path cannot silently
// defeat the typed `token approve --unlimited --yes` ceremony.
func TestContractSend_IntentAckedFromUnlimitedNotConfirm(t *testing.T) {
	from := someAddr(0x01)
	contract := someAddr(0x42)
	svc, _, _ := sendService(t, from)
	addContract(t, svc, "stk", contract, stakingABIJSON)

	base := domain.ContractSendRequest{
		Contract: "stk", Method: "stake", Args: []string{"5000"},
		From: from.Hex(), Network: "mainnet",
	}

	// --yes alone (Yes=true, AckUnlimited=false) must NOT set acked: --yes only skips
	// the TTY confirmation, it is not the unlimited acknowledgement.
	yesOnly := base
	yesOnly.Yes = true
	in, err := svc.resolveContractSendIntent(context.Background(), domain.LocalCLI(), yesOnly, nil)
	if err != nil {
		t.Fatalf("resolveContractSendIntent (--yes only): %v", err)
	}
	in.cc.Close()
	if in.acked {
		t.Error("intent.acked = true for --yes alone; --yes must NOT carry the unlimited ack (the D12 bypass)")
	}

	// --unlimited (AckUnlimited=true) sets acked — the deliberate acknowledgement.
	withAck := base
	withAck.Yes, withAck.AckUnlimited = true, true
	in2, err := svc.resolveContractSendIntent(context.Background(), domain.LocalCLI(), withAck, nil)
	if err != nil {
		t.Fatalf("resolveContractSendIntent (--unlimited --yes): %v", err)
	}
	in2.cc.Close()
	if !in2.acked {
		t.Error("intent.acked = false for --unlimited; the deliberate ack must set Check.Acked")
	}
}

// ── THE CRUX: classifyContractSend rewrites approve(spender,MAX) into KindApprove ──

func TestClassifyContractSend_ApproveBecomesKindApprove(t *testing.T) {
	contract := someAddr(0x42) // the ERC-20
	spender := someAddr(0x0b)

	// Build the EXACT calldata a contract send would carry: approve(spender, 2^256-1).
	parsed, perr := dabi.Codec{}.ParseJSON([]byte(erc20ABIJSON))
	if perr != nil {
		t.Fatalf("ParseJSON: %v", perr)
	}
	maxU := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	args, _, cerr := dabi.Codec{}.CoerceArgs(parsed, "approve", []string{spender.Hex(), maxU.String()}, literalAddrResolver)
	if cerr != nil {
		t.Fatalf("CoerceArgs: %v", cerr)
	}
	data, derr := dabi.Codec{}.PackCall(parsed, "approve", args)
	if derr != nil {
		t.Fatalf("PackCall: %v", derr)
	}

	svc, _, _ := sendService(t, someAddr(0x01))
	in := &Intent{to: contract, data: data, value: big.NewInt(0), isContractSend: true}
	check := policy.Check{Account: someAddr(0x01), Dest: contract} // base check (Dest=contract pre-classify)

	svc.classifyContractSend(in, &check)

	// The Check is REWRITTEN to the spend-equivalent the typed `token approve` emits:
	//   Dest = the DECODED spender (NOT the ERC-20 contract);
	//   Kind = approve (→ KindApprove); Unlimited (the 2^256-1 sentinel);
	//   Token/Asset = the contract; NOT the stage-5b unknown path.
	if check.Dest != spender {
		t.Errorf("classified Dest = %s, want the decoded spender %s (never the contract)", check.Dest.Hex(), spender.Hex())
	}
	if check.Dest == contract {
		t.Fatal("classified Dest is the ERC-20 contract — the spender-as-dest invariant is BROKEN (the bypass)")
	}
	if check.Kind != "approve" || check.KindEnum != policy.KindApprove {
		t.Errorf("classified kind = %q/%d, want approve/KindApprove", check.Kind, check.KindEnum)
	}
	if !check.Unlimited {
		t.Error("classified Unlimited = false, want true (2^256-1 is the sentinel)")
	}
	if !strings.EqualFold(check.Asset, contract.Hex()) {
		t.Errorf("classified Asset = %q, want the contract %s", check.Asset, contract.Hex())
	}
	if check.UnknownCalldata {
		t.Error("a recognized approve must NOT set UnknownCalldata (it is not the stage-5b path)")
	}
	// The classification verdict is recorded for the --dry-run echo.
	if in.classification == nil || in.classification.ClassifiedAs != "approve" || !in.classification.Unlimited {
		t.Errorf("classification verdict = %+v, want approve/unlimited", in.classification)
	}
}

// ── THE STAGE-5b PATH: an unrecognized selector flips the Check to the gate ────

func TestClassifyContractSend_UnknownSelectorFlipsStage5b(t *testing.T) {
	contract := someAddr(0x42)

	// stake(uint256) calldata — NOT a recognized spend-equivalent selector.
	parsed, _ := dabi.Codec{}.ParseJSON([]byte(stakingABIJSON))
	args, _, _ := dabi.Codec{}.CoerceArgs(parsed, "stake", []string{"100"}, literalAddrResolver)
	data, _ := dabi.Codec{}.PackCall(parsed, "stake", args)

	svc, _, _ := sendService(t, someAddr(0x01))
	in := &Intent{to: contract, data: data, value: big.NewInt(0), isContractSend: true, network: "mainnet"}
	check := policy.Check{Account: someAddr(0x01), Dest: contract}

	svc.classifyContractSend(in, &check)

	if !check.UnknownCalldata {
		t.Fatal("an unrecognized selector must set UnknownCalldata (the stage-5b gate)")
	}
	if check.ContractAddr != contract {
		t.Errorf("stage-5b ContractAddr = %s, want the contract %s", check.ContractAddr.Hex(), contract.Hex())
	}
	if check.Selector != "0xa694fc3a" {
		t.Errorf("stage-5b Selector = %q, want 0xa694fc3a (stake)", check.Selector)
	}
	// Dest = the contract (so stage-3b ALSO gates the contract address as destination).
	if check.Dest != contract {
		t.Errorf("stage-5b Dest = %s, want the contract %s", check.Dest.Hex(), contract.Hex())
	}
	if check.KindEnum == policy.KindApprove {
		t.Error("an unrecognized selector must NOT be classified KindApprove")
	}
	if in.classification == nil || in.classification.ClassifiedAs != "unknown" {
		t.Errorf("classification verdict = %+v, want unknown", in.classification)
	}
}

// classifyContractSend is a no-op for a non-contract-send Intent (a plain ETH/token send
// keeps its typed Check untouched).
func TestClassifyContractSend_NoopForNonContractSend(t *testing.T) {
	svc, _, _ := sendService(t, someAddr(0x01))
	in := &Intent{to: someAddr(0x42), data: []byte{0xa9, 0x05, 0x9c, 0xbb}, value: big.NewInt(0), isContractSend: false}
	check := policy.Check{Dest: someAddr(0x99)}
	svc.classifyContractSend(in, &check)
	if check.Dest != someAddr(0x99) || check.UnknownCalldata || in.classification != nil {
		t.Errorf("classifyContractSend mutated a non-contract-send Check: %+v", check)
	}
}

// ── §5.11 PURE encode/decode round-trip (no chain, no policy) ──────────────────

func TestEncodeDecode_RoundTripPure(t *testing.T) {
	svc, _, _ := sendService(t, someAddr(0x01))

	enc, err := svc.EncodeCalldata(context.Background(), domain.LocalCLI(), domain.EncodeRequest{
		Method: "stake",
		Args:   []string{"777"},
		ABI:    domain.ABISource{Sig: "stake(uint256)"},
	})
	if err != nil {
		t.Fatalf("EncodeCalldata: %v", err)
	}
	if !strings.HasPrefix(enc.Calldata, "0xa694fc3a") {
		t.Fatalf("encoded calldata = %q, want stake selector prefix", enc.Calldata)
	}

	dec, err := svc.DecodeCalldata(context.Background(), domain.LocalCLI(), domain.DecodeRequest{
		Calldata: enc.Calldata,
		ABI:      domain.ABISource{Sig: "stake(uint256)"},
	})
	if err != nil {
		t.Fatalf("DecodeCalldata: %v", err)
	}
	if dec.Selector != "0xa694fc3a" {
		t.Errorf("decoded selector = %q, want 0xa694fc3a", dec.Selector)
	}
	if len(dec.Args) != 1 || dec.Args[0].Value != "777" {
		t.Fatalf("decoded args = %+v, want one uint256 777 (round-trip)", dec.Args)
	}
}

// ── ABI-source resolution: registry alias vs --sig precedence ─────────────────

func TestResolveABISource_AliasWinsAndRejectsExplicitConflict(t *testing.T) {
	contract := someAddr(0x42)
	svc, _, _ := sendService(t, someAddr(0x01))
	addContract(t, svc, "stk", contract, stakingABIJSON)

	// A registered alias resolves to the STORED ABI with no explicit source.
	src, err := svc.resolveABISource(context.Background(), "mainnet", "stk", domain.ABISource{})
	if err != nil || src.abi == nil {
		t.Fatalf("resolveABISource(alias) = %v / %v, want the stored ABI", src.abi, err)
	}

	// A registered alias + an explicit --sig is a usage conflict (exit 2): exactly one source.
	_, cerr := svc.resolveABISource(context.Background(), "mainnet", "stk", domain.ABISource{Sig: "stake(uint256)"})
	if cerr == nil {
		t.Fatal("resolveABISource(alias + --sig) must error (ambiguous source)")
	}
	if de := domain.AsError(cerr); !strings.HasPrefix(de.Code, domain.CodeUsage) {
		t.Errorf("ambiguous-source code = %q, want a usage.* code", de.Code)
	}
}

// ── contract registry CRUD (the registry-only resolution wall) ────────────────

func TestContractRegistry_AddListShowRemove(t *testing.T) {
	contract := someAddr(0x42)
	svc, _, _ := sendService(t, someAddr(0x01))

	row, err := svc.ContractAdd(context.Background(), domain.LocalCLI(), domain.ContractAddRequest{
		Alias: "stk", Address: contract.Hex(), ABIJSON: stakingABIJSON, Network: "mainnet",
	})
	if err != nil {
		t.Fatalf("ContractAdd: %v", err)
	}
	if row.Alias != "stk" || row.FuncCount == 0 {
		t.Fatalf("added row = %+v, want alias stk + nonzero functions", row)
	}

	// An INVALID ABI at add → usage.bad_abi, NOT stored.
	if _, aerr := svc.ContractAdd(context.Background(), domain.LocalCLI(), domain.ContractAddRequest{
		Alias: "bad", Address: contract.Hex(), ABIJSON: "{not json", Network: "mainnet",
	}); aerr == nil {
		t.Fatal("ContractAdd with an invalid ABI must error (usage.bad_abi)")
	} else if de := domain.AsError(aerr); de.Code != "usage.bad_abi" {
		t.Errorf("invalid-ABI code = %q, want usage.bad_abi", de.Code)
	}

	lst, err := svc.ContractList(context.Background(), domain.LocalCLI(), domain.ContractListRequest{Network: "mainnet"})
	if err != nil {
		t.Fatalf("ContractList: %v", err)
	}
	if len(lst.Contracts) != 1 || lst.Contracts[0].Alias != "stk" {
		t.Fatalf("list = %+v, want one alias stk (bad never stored)", lst.Contracts)
	}

	show, err := svc.ContractShow(context.Background(), domain.LocalCLI(), domain.ContractShowRequest{Alias: "stk", Network: "mainnet"})
	if err != nil {
		t.Fatalf("ContractShow: %v", err)
	}
	if len(show.Functions) == 0 {
		t.Error("ContractShow returned no function signatures")
	}

	if _, rerr := svc.ContractRemove(context.Background(), domain.LocalCLI(), domain.ContractRemoveRequest{Alias: "stk", Network: "mainnet"}); rerr != nil {
		t.Fatalf("ContractRemove: %v", rerr)
	}
	if _, serr := svc.ContractShow(context.Background(), domain.LocalCLI(), domain.ContractShowRequest{Alias: "stk", Network: "mainnet"}); serr == nil {
		t.Fatal("ContractShow after remove must error (ref.not_found)")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// addContract registers a contract alias in the service's registry for a test.
func addContract(t *testing.T, svc *Service, alias string, addr common.Address, abiJSON string) {
	t.Helper()
	if _, err := svc.ContractAdd(context.Background(), domain.LocalCLI(), domain.ContractAddRequest{
		Alias: alias, Address: addr.Hex(), ABIJSON: abiJSON, Network: "mainnet",
	}); err != nil {
		t.Fatalf("addContract %s: %v", alias, err)
	}
}

// literalAddrResolver is a CoerceArgs address resolver that accepts only raw 0x (the
// unit tests pass literal addresses; ENS/contact resolution is covered by the
// integration test).
func literalAddrResolver(s string) (common.Address, dabi.AddrProvenance, error) {
	a := common.HexToAddress(s)
	return a, dabi.AddrProvenance{Input: s, Addr: a, Via: "literal"}, nil
}
