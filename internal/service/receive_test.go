package service

import (
	"context"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/registry"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// receive_test.go drives the §5.8 detection engine through the chain/fake: no real
// network, deterministic blocks/logs/balances/receipts. Each test programs the
// fake so the loop terminates on the first poll (complete) or via an advancing
// clock (timeout).

// balanceClient wraps a *fake.Client and overrides Balance with a function so a
// test can vary the balance between the listen-start baseline read and the in-loop
// head reads (the fake's Balances map is static). It is a thin chain.Client
// decorator — all other methods delegate to the embedded fake.
type balanceClient struct {
	*fake.Client
	balanceFn func(block *big.Int) *big.Int
	headFn    func() uint64 // optional: advancing head; nil ⇒ delegate to fake.BlockNum

	mu        sync.Mutex
	balBlocks []*big.Int // every block arg passed to Balance (for the carry-forward assertion)
}

func (b *balanceClient) Balance(ctx context.Context, a common.Address, block *big.Int) (*big.Int, error) {
	b.mu.Lock()
	b.balBlocks = append(b.balBlocks, block)
	b.mu.Unlock()
	if b.Err != nil {
		return nil, b.Err
	}
	return b.balanceFn(block), nil
}

func (b *balanceClient) BlockNumber(ctx context.Context) (uint64, error) {
	if b.headFn != nil {
		return b.headFn(), nil
	}
	return b.Client.BlockNumber(ctx)
}

func (b *balanceClient) blocksSeen() []*big.Int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*big.Int, len(b.balBlocks))
	copy(out, b.balBlocks)
	return out
}

var _ chain.Client = (*balanceClient)(nil)

// receiveService opens an isolated service wired with a chain client and an
// advancing clock so any deadline is reachable. step is the per-clock-call advance.
func receiveService(t *testing.T, cc chain.Client, step time.Duration) *Service {
	t.Helper()
	isolate(t)
	svc, err := Open(context.Background(), Options{
		Clock: advancingClock(time.Date(2026, 6, 16, 17, 0, 0, 0, time.UTC), step),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.chains = &stubProvider{cc: cc}
	return svc
}

// addTestToken registers an ERC-20 alias→contract on mainnet so resolveAsset
// resolves it registry-only (no on-chain decimals read needed).
func addTestToken(t *testing.T, svc *Service, alias string, contract common.Address, decimals uint8) {
	t.Helper()
	if err := svc.tokens.Add(context.Background(), "mainnet", registry.Token{
		Alias:    alias,
		Address:  contract,
		Kind:     registry.KindERC20,
		Decimals: decimals,
	}); err != nil {
		t.Fatalf("token add: %v", err)
	}
}

// collectSink captures every emitted event for assertions (concurrency-safe).
type collectSink struct {
	mu sync.Mutex
	ev []domain.Event
}

func (c *collectSink) sink() domain.EventSink {
	return func(e domain.Event) {
		c.mu.Lock()
		c.ev = append(c.ev, e)
		c.mu.Unlock()
	}
}

func (c *collectSink) kinds() []domain.EventKind {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]domain.EventKind, len(c.ev))
	for i, e := range c.ev {
		out[i] = e.Kind
	}
	return out
}

func (c *collectSink) has(k domain.EventKind) bool {
	for _, got := range c.kinds() {
		if got == k {
			return true
		}
	}
	return false
}

func (c *collectSink) count(k domain.EventKind) int {
	n := 0
	for _, got := range c.kinds() {
		if got == k {
			n++
		}
	}
	return n
}

func (c *collectSink) first(k domain.EventKind) (domain.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.ev {
		if e.Kind == k {
			return e, true
		}
	}
	return domain.Event{}, false
}

// erc20TransferLog builds an ERC-20 Transfer log (3 topics, 32-byte value data).
func erc20TransferLog(token, from, to common.Address, value *big.Int, block uint64, blockHash common.Hash, idx uint) types.Log {
	var data [32]byte
	value.FillBytes(data[:])
	return types.Log{
		Address:     token,
		Topics:      []common.Hash{transferTopic0, hashOfAddr(from), hashOfAddr(to)},
		Data:        data[:],
		BlockNumber: block,
		BlockHash:   blockHash,
		TxHash:      common.BytesToHash([]byte{byte(idx + 1), 0x10, 0x9}),
		Index:       idx,
	}
}

func hashOfAddr(a common.Address) common.Hash { return common.BytesToHash(a.Bytes()) }

// signedValueTx builds a real signed ETH value tx so types.Sender recovers a
// sender in the block scan. Returns the tx.
func signedValueTx(t *testing.T, to common.Address, valueWei *big.Int, nonce uint64) *types.Transaction {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := types.LatestSignerForChainID(big.NewInt(1))
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(1),
		Nonce:     nonce,
		To:        &to,
		Value:     valueWei,
		Gas:       21000,
		GasFeeCap: gwei(50),
		GasTipCap: gwei(1),
	})
	signed, err := types.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	return signed
}

// noTxBlocks returns a BlockByNumber hook that yields an empty block at any height.
func noTxBlocks() func(context.Context, *big.Int, bool) (*types.Block, error) {
	return func(_ context.Context, n *big.Int, _ bool) (*types.Block, error) {
		return blockWithTxs(n.Uint64(), nil), nil
	}
}

// rampHead returns a head function that yields each value in seq in turn, then
// repeats the last value forever. It models the chain head advancing across polls.
func rampHead(seq ...uint64) func() uint64 {
	i := 0
	return func() uint64 {
		v := seq[i]
		if i < len(seq)-1 {
			i++
		}
		return v
	}
}

// ── ERC-20 log detection → confirmed → complete ──

func TestReceive_ERC20_LogDetection_Complete(t *testing.T) {
	listen := someAddr(1)
	token := someAddr(2)
	payer := someAddr(3)
	bh := common.HexToHash("0x77aa")
	f := fake.New()
	f.BlockNum = 10 // head ≥ detection block(8) + confirmations(mainnet=2)
	log := erc20TransferLog(token, payer, listen, big.NewInt(100_000_000), 8, bh, 7)
	f.FilterLogsFn = func(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		return []types.Log{log}, nil
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: bh, GasUsed: 50000, EffectiveGasPrice: gwei(20)}, nil
	}

	svc := receiveService(t, f, time.Second)
	addTestToken(t, svc, "testtok", token, 6)
	cs := &collectSink{}
	// --amount is DISPLAY units; for USDC (decimals 6) "100" scales to 100000000 base
	// units — exactly the on-chain log value. The wire amounts stay base units.
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Token: token.Hex(), Amount: "100"}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "complete" || res.Exit != 0 {
		t.Fatalf("status=%q exit=%d, want complete/0", res.Status, res.Exit)
	}
	if res.CumulativeConfirmed != "100000000" {
		t.Fatalf("cumulative = %q, want 100000000", res.CumulativeConfirmed)
	}
	// The listening line's target.amount is the SCALED base-unit value (§5.8 example:
	// USDC --amount 100 ⇒ target.amount "100000000"), not the raw "100".
	lst0, _ := cs.first(domain.EvListening)
	if lst0.TargetSpec == nil || lst0.TargetSpec.Amount != "100000000" {
		t.Fatalf("listening target.amount = %+v, want 100000000 (display 100 × 10^6)", lst0.TargetSpec)
	}
	for _, want := range []domain.EventKind{domain.EvListening, domain.EvDetected, domain.EvConfirmed, domain.EvComplete} {
		if !cs.has(want) {
			t.Errorf("missing event %q in stream %v", want, cs.kinds())
		}
	}
	det, _ := cs.first(domain.EvDetected)
	if det.Attribution != domain.AttribLog {
		t.Errorf("detected attribution = %q, want log", det.Attribution)
	}
	if det.LogIndex == nil || *det.LogIndex != 7 {
		t.Errorf("detected log_index = %v, want 7", det.LogIndex)
	}
	if k := cs.kinds(); len(k) == 0 || k[0] != domain.EvListening {
		t.Errorf("first event = %v, want listening (address up front)", k)
	}
	cmp, _ := cs.first(domain.EvComplete)
	if len(cmp.TxHashes) != 1 {
		t.Errorf("complete tx_hashes = %v, want 1", cmp.TxHashes)
	}
	// The listening line carries from_block + chain_id + the asset/target spec.
	lst, _ := cs.first(domain.EvListening)
	if lst.Asset == nil || lst.Asset.Kind != "erc20" {
		t.Errorf("listening asset = %+v, want erc20", lst.Asset)
	}
	if lst.TargetSpec == nil || lst.TargetSpec.Confirmations != 2 {
		t.Errorf("listening target confirmations = %+v, want 2 (mainnet default)", lst.TargetSpec)
	}
	if lst.TargetSpec.Timeout != nil {
		t.Errorf("unbounded wait must emit timeout:null, got %v", *lst.TargetSpec.Timeout)
	}
}

// ── ERC-20 --amount is DISPLAY units scaled by decimals (matches `tx send`/§5.8) ──
//
// A non-18-decimal token (USDC, 6) is the regression that the old raw-base-units
// parse passed only by accident: --amount 100 must resolve target.amount to
// 100000000 (100 × 10^6), and a 99.9-USDC inbound (99900000 base) must NOT complete
// the listen — under the old code the target was 100 base units (1e-16 USDC) and any
// dust tripped it.
func TestReceive_ERC20_AmountDisplayUnits_Scaled(t *testing.T) {
	listen := someAddr(1)
	token := someAddr(2)
	bh := common.HexToHash("0x77aa")
	f := fake.New()
	f.BlockNum = 10
	// A 99.9-USDC inbound (99_900_000 base units) — short of the 100-USDC target.
	log := erc20TransferLog(token, someAddr(3), listen, big.NewInt(99_900_000), 8, bh, 0)
	f.FilterLogsFn = func(_ context.Context, _ ethereum.FilterQuery) ([]types.Log, error) {
		return []types.Log{log}, nil
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: bh}, nil
	}
	svc := receiveService(t, f, 200*time.Millisecond)
	addTestToken(t, svc, "myusdc", token, 6) // non-bundled alias; USDC decimals (6)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Token: token.Hex(), Amount: "100",
			Timeout: domain.Duration{D: time.Second}}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	// target.amount on the wire is the SCALED base-unit value, not the raw "100".
	lst, _ := cs.first(domain.EvListening)
	if lst.TargetSpec == nil || lst.TargetSpec.Amount != "100000000" {
		t.Fatalf("listening target.amount = %+v, want 100000000 (display 100 × 10^6)", lst.TargetSpec)
	}
	if res.Target.Amount != "100000000" {
		t.Fatalf("result target.amount = %q, want 100000000", res.Target.Amount)
	}
	// 99.9 USDC (99900000 base) is BELOW the 100-USDC target ⇒ must time out, not
	// complete. The old raw-base parse (target=100) would have completed on this.
	if res.Status != "timeout" {
		t.Fatalf("status = %q, want timeout (99.9 USDC does not satisfy a 100-USDC target)", res.Status)
	}
	if res.CumulativeConfirmed != "99900000" {
		t.Fatalf("cumulative = %q, want 99900000 (the confirmed 99.9 USDC)", res.CumulativeConfirmed)
	}
	// The resume --amount round-trips back to DISPLAY units: remaining 100000 base
	// (0.1 USDC) ⇒ "0.1", which re-parses through ParseTokenAmount at full precision.
	to, _ := cs.first(domain.EvTimeout)
	if !strings.Contains(to.Resume, "--amount 0.1") {
		t.Errorf("resume %q missing --amount 0.1 (full-precision display remainder)", to.Resume)
	}
}

// ── ETH block-scan detection (attribution:"tx") ──

func TestReceive_ETH_BlockScan_Complete(t *testing.T) {
	listen := someAddr(1)
	tx := signedValueTx(t, listen, eth(1), 0)
	blk := blockWithTxs(8, []*types.Transaction{tx})

	f := fake.New()
	f.BlockByNumberFn = func(_ context.Context, n *big.Int, _ bool) (*types.Block, error) {
		if n != nil && n.Uint64() == 8 {
			return blk, nil
		}
		return blockWithTxs(n.Uint64(), nil), nil
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: blk.Hash(), GasUsed: 21000, EffectiveGasPrice: gwei(10)}, nil
	}
	// The listen starts at head 8 (so block 8 is scanned forward), then the head
	// advances to 10 to reach the confirmation target — the realistic flow. The
	// baseline balance is 0 at listen start and 1 ETH after the inbound, so the
	// balance-delta term nets to zero against the attributed inbound (no phantom).
	var balCalls int
	cc := &balanceClient{
		Client: f,
		balanceFn: func(_ *big.Int) *big.Int {
			balCalls++
			if balCalls == 1 {
				return big.NewInt(0) // baseline at listen start
			}
			return eth(1) // after the inbound landed
		},
		headFn: rampHead(8, 8, 10),
	}

	svc := receiveService(t, cc, time.Second)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Amount: "1"}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "complete" || res.Exit != 0 {
		t.Fatalf("status=%q exit=%d, want complete/0", res.Status, res.Exit)
	}
	det, ok := cs.first(domain.EvDetected)
	if !ok {
		t.Fatal("no detected event")
	}
	if det.Attribution != domain.AttribTx {
		t.Errorf("attribution = %q, want tx (block-scan)", det.Attribution)
	}
	if res.CumulativeConfirmed != eth(1).String() {
		t.Errorf("cumulative = %q, want %s", res.CumulativeConfirmed, eth(1))
	}
}

// ── balance-delta detection (internal transfer): block-scan sees nothing but the
//    head balance rose from the baseline; the safety net catches it. ──

func TestReceive_ETH_BalanceDelta_InternalTransfer(t *testing.T) {
	listen := someAddr(1)
	f := fake.New()
	f.BlockByNumberFn = noTxBlocks() // no inbound tx anywhere (internal CALL transfer)
	var calls int
	cc := &balanceClient{
		Client: f,
		balanceFn: func(_ *big.Int) *big.Int {
			calls++
			if calls == 1 {
				return big.NewInt(0) // baseline at listen start
			}
			return wei("500000000000000000") // 0.5 ETH arrived internally
		},
		// head 10 at listen start + first scan (delta detection at block 10), then
		// advances to 12 so that detection reaches the 2-confirmation target.
		headFn: rampHead(10, 10, 12),
	}

	svc := receiveService(t, cc, time.Second)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Amount: "0.5"}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "complete" {
		t.Fatalf("status = %q, want complete (balance-delta safety net)", res.Status)
	}
	det, ok := cs.first(domain.EvDetected)
	if !ok {
		t.Fatal("no detected event from the balance-delta path")
	}
	if det.Attribution != domain.AttribBalanceDelta {
		t.Errorf("attribution = %q, want balance-delta", det.Attribution)
	}
	if det.TxHash != "" {
		t.Errorf("balance-delta detection must carry no tx_hash, got %q", det.TxHash)
	}
}

// ── --exact: a balance-delta detection cannot satisfy --exact (review non-negotiable) ──

func TestReceive_Exact_BalanceDeltaCannotSatisfy(t *testing.T) {
	listen := someAddr(1)
	f := fake.New()
	f.BlockByNumberFn = noTxBlocks()
	var calls int
	cc := &balanceClient{
		Client: f,
		balanceFn: func(_ *big.Int) *big.Int {
			calls++
			if calls == 1 {
				return big.NewInt(0)
			}
			return eth(1) // exactly 1 ETH arrived, but via balance-delta (no tx)
		},
		// head 10 at baseline + poll-1 scan (balance-delta detection at block 10), then
		// advances to 12 so that detection reaches the 2-confirmation target and CONFIRMS
		// — proving the inflow was counted before --exact rejects it.
		headFn: rampHead(10, 10, 12),
	}
	svc := receiveService(t, cc, 150*time.Millisecond)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Amount: "1", Exact: true, Timeout: domain.Duration{D: 2 * time.Second}}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	// NON-TAUTOLOGY: prove the engine actually DETECTED + CONFIRMED the balance-delta
	// inflow of exactly 1 ETH — so the timeout is because --exact REJECTS an
	// unattributable confirmed inflow, not because nothing was ever detected.
	det, ok := cs.first(domain.EvDetected)
	if !ok {
		t.Fatal("no detected event — the balance-delta inflow was never detected, so this would time out vacuously")
	}
	if det.Attribution != domain.AttribBalanceDelta {
		t.Fatalf("detected attribution = %q, want balance-delta (the unattributable inflow under test)", det.Attribution)
	}
	if !cs.has(domain.EvConfirmed) {
		t.Fatal("the balance-delta detection must reach CONFIRMED before --exact rejects it")
	}
	// cumulative_confirmed reached the full 1-ETH value — the inflow was counted, yet
	// --exact still refuses it (balance-delta has no single transfer equal to X).
	if res.CumulativeConfirmed != eth(1).String() {
		t.Fatalf("cumulative_confirmed = %q, want %s (the confirmed balance-delta inflow)", res.CumulativeConfirmed, eth(1))
	}
	if res.Status != "timeout" || res.Exit != 8 {
		t.Fatalf("status=%q exit=%d, want timeout/8 (a CONFIRMED balance-delta of the exact value still cannot satisfy --exact)", res.Status, res.Exit)
	}
}

// ── --exact IS satisfied by an attributable log of the exact value ──

func TestReceive_Exact_AttributableLogSatisfies(t *testing.T) {
	listen := someAddr(1)
	token := someAddr(2)
	bh := common.HexToHash("0x77aa")
	f := fake.New()
	f.BlockNum = 10
	log := erc20TransferLog(token, someAddr(3), listen, big.NewInt(100), 8, bh, 0)
	f.FilterLogsFn = func(_ context.Context, _ ethereum.FilterQuery) ([]types.Log, error) {
		return []types.Log{log}, nil
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: bh}, nil
	}
	svc := receiveService(t, f, time.Second)
	addTestToken(t, svc, "tt", token, 0)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Token: token.Hex(), Amount: "100", Exact: true}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "complete" || res.Exit != 0 {
		t.Fatalf("status=%q exit=%d, want complete/0 (an attributable log of exactly 100 satisfies --exact)", res.Status, res.Exit)
	}
}

// ── cumulative multi-transfer: two confirmed inbound sum to the target ──

func TestReceive_Cumulative_MultiTransfer(t *testing.T) {
	listen := someAddr(1)
	token := someAddr(2)
	bh := common.HexToHash("0x77aa")
	f := fake.New()
	f.BlockNum = 10
	logA := erc20TransferLog(token, someAddr(3), listen, big.NewInt(60), 8, bh, 0)
	logB := erc20TransferLog(token, someAddr(4), listen, big.NewInt(40), 8, bh, 1)
	f.FilterLogsFn = func(_ context.Context, _ ethereum.FilterQuery) ([]types.Log, error) {
		return []types.Log{logA, logB}, nil
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: bh}, nil
	}
	svc := receiveService(t, f, time.Second)
	addTestToken(t, svc, "tt", token, 0)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Token: token.Hex(), Amount: "100"}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "complete" {
		t.Fatalf("status = %q, want complete", res.Status)
	}
	if res.CumulativeConfirmed != "100" {
		t.Fatalf("cumulative = %q, want 100 (60+40)", res.CumulativeConfirmed)
	}
	if n := cs.count(domain.EvConfirmed); n != 2 {
		t.Errorf("confirmed events = %d, want 2 (per-transfer)", n)
	}
	cmp, _ := cs.first(domain.EvComplete)
	if len(cmp.TxHashes) != 2 {
		t.Errorf("complete tx_hashes = %d, want 2", len(cmp.TxHashes))
	}
}

// ── reorg of a PENDING (never-confirmed) detection: evidence vanishes before it
//    ever reaches the confirmation target, so it is dropped from pending and emits
//    reorged. (This is the original case; it does NOT exercise the confirmed-set
//    subtraction — see TestReceive_Reorg_SubtractsAfterConfirm for that.) Here the
//    listen has a confTarget high enough that the detection stays pending: a tiny
//    confirmation budget keeps it in the pending set across the first poll, then the
//    re-verify fails. We force this with --confirmations so head−B+1 < target. ──

func TestReceive_Reorg_PendingDroppedBeforeConfirm(t *testing.T) {
	listen := someAddr(1)
	token := someAddr(2)
	bh := common.HexToHash("0x77aa")
	const detBlock = 8
	f := fake.New()
	log := erc20TransferLog(token, someAddr(3), listen, big.NewInt(100), detBlock, bh, 0)

	// The scan returns the log (→ pending). With --confirmations 5 and head advancing
	// 10→11→13, the detection at block 8 reaches conf=5 only on a later poll; that
	// re-verify (a [8,8] query at the DETECTION block) returns a DIFFERENT block hash
	// ⇒ reorged out of PENDING before it ever confirmed. A re-verify is identified by
	// its single-block window AT the detection block (FromBlock==8), distinct from the
	// scan window at the head.
	isReverify := func(q ethereum.FilterQuery) bool {
		return q.FromBlock != nil && q.ToBlock != nil &&
			q.FromBlock.Cmp(q.ToBlock) == 0 && q.FromBlock.Uint64() == detBlock
	}
	f.FilterLogsFn = func(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		if isReverify(q) {
			reorged := log
			reorged.BlockHash = common.HexToHash("0xdead")
			return []types.Log{reorged}, nil
		}
		return []types.Log{log}, nil // a scan
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: bh}, nil
	}
	cc := &balanceClient{Client: f, headFn: rampHead(10, 11, 13), balanceFn: func(_ *big.Int) *big.Int { return big.NewInt(0) }}
	confs := uint64(5)
	svc := receiveService(t, cc, 150*time.Millisecond)
	addTestToken(t, svc, "tt", token, 0)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Token: token.Hex(), Amount: "100", Confirmations: &confs, Timeout: domain.Duration{D: 2 * time.Second}}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !cs.has(domain.EvReorged) {
		t.Fatalf("expected a reorged event; stream = %v", cs.kinds())
	}
	// It was NEVER confirmed (dropped from pending), so cumulative stays 0 and no
	// confirmed line ever fired.
	if cs.has(domain.EvConfirmed) {
		t.Errorf("a never-confirmed detection must not emit confirmed; stream = %v", cs.kinds())
	}
	if res.Status != "timeout" {
		t.Fatalf("status = %q, want timeout", res.Status)
	}
	if res.CumulativeConfirmed != "0" {
		t.Fatalf("cumulative = %q, want 0", res.CumulativeConfirmed)
	}
}

// ── reorg of a CONFIRMED detection: the real confirmed-set subtraction path
//    (st.cumConfirmed.Sub at receive.go). A detection first CONFIRMS (cumulative +=
//    value, EvConfirmed fires) on poll 1, then on a later poll its evidence vanishes
//    and the confirmed-set reverify fails ⇒ EvReorged + cumulative -= value back to
//    0. The target is set ABOVE the single transfer so the first confirmation does
//    NOT complete the listen (else the loop would return before the reorg poll). The
//    test asserts EvConfirmed fired BEFORE EvReorged and that the final cumulative is
//    the result of a real subtraction (it was 100, not a never-incremented 0). ──

func TestReceive_Reorg_SubtractsAfterConfirm(t *testing.T) {
	listen := someAddr(1)
	token := someAddr(2)
	bh := common.HexToHash("0x77aa")
	const detBlock = 8
	f := fake.New()
	log := erc20TransferLog(token, someAddr(3), listen, big.NewInt(100), detBlock, bh, 0)

	// A re-verify is a single-block query AT the detection block (FromBlock==8),
	// distinct from the scan window at the head. The FIRST re-verify succeeds (→
	// confirmed, cum=100); every LATER re-verify fails with a mismatched block hash (→
	// confirmed-set reorg, cum-=100). Scans always return the live log (deduped after
	// the first detection).
	isReverify := func(q ethereum.FilterQuery) bool {
		return q.FromBlock != nil && q.ToBlock != nil &&
			q.FromBlock.Cmp(q.ToBlock) == 0 && q.FromBlock.Uint64() == detBlock
	}
	var reverifyCalls int
	f.FilterLogsFn = func(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		if isReverify(q) {
			reverifyCalls++
			if reverifyCalls == 1 {
				return []types.Log{log}, nil // first reverify: matches ⇒ confirm
			}
			reorged := log
			reorged.BlockHash = common.HexToHash("0xdead") // later reverify: mismatch ⇒ reorg
			return []types.Log{reorged}, nil
		}
		return []types.Log{log}, nil
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: bh}, nil
	}
	// head 10 from the start (conf=3 ≥ confTarget 2 on poll 1 ⇒ confirms immediately).
	cc := &balanceClient{Client: f, headFn: rampHead(10), balanceFn: func(_ *big.Int) *big.Int { return big.NewInt(0) }}
	svc := receiveService(t, cc, 150*time.Millisecond)
	addTestToken(t, svc, "tt", token, 0)
	cs := &collectSink{}
	// Target 150 > the single 100 transfer, so the first confirmation does NOT
	// complete the listen — the loop continues to the poll where the reorg subtracts.
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Token: token.Hex(), Amount: "150", Timeout: domain.Duration{D: 2 * time.Second}}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !cs.has(domain.EvConfirmed) {
		t.Fatalf("the detection must CONFIRM first (cum += 100); stream = %v", cs.kinds())
	}
	if !cs.has(domain.EvReorged) {
		t.Fatalf("the confirmed detection must then reorg out; stream = %v", cs.kinds())
	}
	// EvConfirmed fired BEFORE EvReorged — proving we subtracted from a value that was
	// actually counted, not a never-incremented zero.
	ks := cs.kinds()
	var confirmedAt, reorgedAt = -1, -1
	for i, k := range ks {
		if k == domain.EvConfirmed && confirmedAt == -1 {
			confirmedAt = i
		}
		if k == domain.EvReorged && reorgedAt == -1 {
			reorgedAt = i
		}
	}
	if confirmedAt == -1 || reorgedAt == -1 || confirmedAt >= reorgedAt {
		t.Fatalf("expected confirmed BEFORE reorged; confirmedAt=%d reorgedAt=%d stream=%v", confirmedAt, reorgedAt, ks)
	}
	// The confirmed line carried cumulative 100 (the increment really happened) …
	conf, _ := cs.first(domain.EvConfirmed)
	if conf.CumulativeConfirmed != "100" {
		t.Errorf("confirmed cumulative = %q, want 100 (the increment)", conf.CumulativeConfirmed)
	}
	// … and after the reorg subtracted it, the final cumulative is back to 0.
	if res.Status != "timeout" {
		t.Fatalf("status = %q, want timeout (target 150 unmet after the subtraction)", res.Status)
	}
	if res.CumulativeConfirmed != "0" {
		t.Fatalf("cumulative after the confirmed-set reorg = %q, want 0 (100 confirmed then subtracted)", res.CumulativeConfirmed)
	}
}

// ── timeout → exit 8, resume string with remaining at FULL precision ──

func TestReceive_Timeout_ResumeFullPrecision(t *testing.T) {
	listen := someAddr(1)
	f := fake.New()
	f.BlockNum = 100
	f.BlockByNumberFn = noTxBlocks()
	cc := &balanceClient{Client: f, balanceFn: func(_ *big.Int) *big.Int { return big.NewInt(0) }}

	svc := receiveService(t, cc, 500*time.Millisecond)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Amount: "5", Timeout: domain.Duration{D: time.Second}}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "timeout" || res.Exit != 8 {
		t.Fatalf("status=%q exit=%d, want timeout/8", res.Status, res.Exit)
	}
	if res.Remaining != eth(5).String() {
		t.Fatalf("remaining = %q, want %s (full precision, never rounded down)", res.Remaining, eth(5))
	}
	to, _ := cs.first(domain.EvTimeout)
	if to.Resume == "" {
		t.Fatal("timeout must carry a resume string")
	}
	if !strings.Contains(to.Resume, "--amount 5") {
		t.Errorf("resume %q missing --amount 5", to.Resume)
	}
	if !strings.Contains(to.Resume, "--from-block 101") { // last_scanned=100 ⇒ +1
		t.Errorf("resume %q missing --from-block 101", to.Resume)
	}
	if to.Note != "verify balance before resuming" {
		t.Errorf("eth timeout note = %q, want the verify-balance note", to.Note)
	}
}

// ── carry-forward baseline: the listen-start baseline reads at the HEAD (nil); the
//    in-loop reads read at the CURRENT RECENT HEAD (the just-scanned block `to`),
//    NEVER re-querying a fixed historical block across polls (§5.8 statelessness).
//    The TOCTOU fix aligns the in-loop balance read with the [from,to] scan window
//    (block `to`), so it is no longer "latest" (nil) — but it is still a fresh recent
//    head every poll, never the pinned listen-start block. ──

func TestReceive_ETH_BaselineCarryForward_NoFixedBlockReQuery(t *testing.T) {
	listen := someAddr(1)
	f := fake.New()
	f.BlockByNumberFn = noTxBlocks()
	cc := &balanceClient{
		Client:    f,
		balanceFn: func(_ *big.Int) *big.Int { return big.NewInt(0) },
		// The head advances every poll (50, 51, 52, …) — so the in-loop balance read
		// at `to` reads a DIFFERENT recent head each poll, never a single fixed block.
		headFn: rampHead(50, 51, 52, 53, 54, 55, 56),
	}

	svc := receiveService(t, cc, 100*time.Millisecond)
	cs := &collectSink{}
	_, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Amount: "1", Timeout: domain.Duration{D: time.Second}}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	seen := cc.blocksSeen()
	if len(seen) == 0 {
		t.Fatal("expected at least the baseline Balance call")
	}
	// Call 0 is the listen-start baseline: read at the head (nil = latest).
	if seen[0] != nil {
		t.Errorf("baseline Balance call used a fixed block %s; the listen-start baseline reads the HEAD (nil)", seen[0])
	}
	// Every in-loop read is at a recent head — and across polls those heads ADVANCE
	// (50,51,52,…), proving the read is never pinned to a single fixed historical block.
	var lastInLoop *big.Int
	distinct := map[string]bool{}
	for i, b := range seen[1:] {
		if b == nil {
			t.Errorf("in-loop Balance call %d read latest (nil); after the TOCTOU fix it must read the exact scanned head block", i+1)
			continue
		}
		distinct[b.String()] = true
		lastInLoop = b
	}
	if lastInLoop != nil && len(distinct) < 2 {
		t.Errorf("in-loop Balance reads never advanced (all at block %s); a fixed-block re-query is exactly what carry-forward forbids", lastInLoop)
	}
}

// ── TOCTOU: the chain advancing one block between BlockNumber and Balance must NOT
//    fabricate a phantom balance-delta detection nor double-count (issue #2). The
//    head balance is read at the SCANNED block `to`, not "latest", so an inbound
//    mined in to+1 is invisible to this poll's delta (it is detected next poll as a
//    bound attribution:"tx" instead — counted exactly once). ──

func TestReceive_ETH_BalanceDelta_NoPhantomOnHeadAdvance(t *testing.T) {
	listen := someAddr(1)
	// The inbound tx lands in block 11 (= to+1 relative to the first poll's scanned
	// head 10). The first poll scans [.,10] and must read the balance AT 10 (still 0),
	// so no phantom balance-delta fires; the second poll scans block 11 and detects
	// the tx as attribution:"tx" exactly once.
	tx := signedValueTx(t, listen, eth(1), 0)
	blk11 := blockWithTxs(11, []*types.Transaction{tx})
	f := fake.New()
	f.BlockByNumberFn = func(_ context.Context, n *big.Int, _ bool) (*types.Block, error) {
		if n.Uint64() == 11 {
			return blk11, nil
		}
		return blockWithTxs(n.Uint64(), nil), nil
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: blk11.Hash(), GasUsed: 21000, EffectiveGasPrice: gwei(10)}, nil
	}
	// head ramps 10 → 11 → 13 (so block 11 reaches the 2-conf mainnet target).
	cc := &balanceClient{
		Client: f,
		balanceFn: func(block *big.Int) *big.Int {
			// Balance is 1 ETH only once block 11 is included (block arg ≥ 11) or at
			// latest (nil). Reading at block 10 (the first poll's scanned head) returns
			// 0 — the TOCTOU guard: the to+1 inbound is NOT visible to poll 1's delta.
			if block == nil {
				return big.NewInt(0) // baseline at listen start
			}
			if block.Uint64() >= 11 {
				return eth(1)
			}
			return big.NewInt(0)
		},
		headFn: rampHead(10, 11, 13),
	}
	svc := receiveService(t, cc, time.Second)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Amount: "1"}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "complete" {
		t.Fatalf("status = %q, want complete", res.Status)
	}
	// EXACTLY ONE detection, attributed to the tx — no phantom balance-delta, no
	// double-count. (Old "latest" read would have seen 1 ETH on poll 1 with directIn=0
	// ⇒ a phantom balance-delta detection, then re-detected the tx on poll 2 ⇒ 2×.)
	if n := cs.count(domain.EvDetected); n != 1 {
		t.Fatalf("detected events = %d, want exactly 1 (no phantom / no double-count); kinds=%v", n, cs.kinds())
	}
	det, _ := cs.first(domain.EvDetected)
	if det.Attribution != domain.AttribTx {
		t.Errorf("detection attribution = %q, want tx (the bound inbound, not a phantom balance-delta)", det.Attribution)
	}
	if res.CumulativeConfirmed != eth(1).String() {
		t.Errorf("cumulative = %q, want %s (counted exactly once)", res.CumulativeConfirmed, eth(1))
	}
}

// ── resume via --from-block scans the gap (no re-query of a fixed historical block) ──

func TestReceive_Resume_FromBlockScansGap(t *testing.T) {
	listen := someAddr(1)
	token := someAddr(2)
	bh := common.HexToHash("0x77aa")
	f := fake.New()
	f.BlockNum = 30
	// The payment is at block 25 (within the resumed [21,30] window).
	log := erc20TransferLog(token, someAddr(3), listen, big.NewInt(100), 25, bh, 0)
	seenFrom := ^uint64(0)
	f.FilterLogsFn = func(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		if q.FromBlock != nil && q.FromBlock.Uint64() < seenFrom {
			seenFrom = q.FromBlock.Uint64()
		}
		return []types.Log{log}, nil
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: bh}, nil
	}
	svc := receiveService(t, f, time.Second)
	addTestToken(t, svc, "tt", token, 0)
	from := uint64(21)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Token: token.Hex(), Amount: "100", FromBlock: &from}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "complete" {
		t.Fatalf("status = %q, want complete (resumed listen detects the gap payment)", res.Status)
	}
	// The first scanned block must be the resume from-block (21), not the head minus
	// lookback — the resume contract.
	lst, _ := cs.first(domain.EvListening)
	if lst.FromBlock != 21 {
		t.Errorf("listening from_block = %d, want 21 (the resume baseline)", lst.FromBlock)
	}
	if seenFrom != 21 {
		t.Errorf("first FilterLogs FromBlock = %d, want 21", seenFrom)
	}
}

// ── any-inbound mode: no amount + no asset flags ⇒ any inbound ETH completes ──

func TestReceive_AnyInbound_ETH(t *testing.T) {
	listen := someAddr(1)
	tx := signedValueTx(t, listen, wei("123"), 0)
	blk := blockWithTxs(8, []*types.Transaction{tx})
	f := fake.New()
	f.BlockByNumberFn = func(_ context.Context, n *big.Int, _ bool) (*types.Block, error) {
		if n.Uint64() == 8 {
			return blk, nil
		}
		return blockWithTxs(n.Uint64(), nil), nil
	}
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: blk.Hash()}, nil
	}
	var balCalls int
	cc := &balanceClient{
		Client: f,
		balanceFn: func(_ *big.Int) *big.Int {
			balCalls++
			if balCalls == 1 {
				return big.NewInt(0)
			}
			return wei("123")
		},
		headFn: rampHead(8, 8, 10),
	}
	svc := receiveService(t, cc, time.Second)
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex()}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "complete" {
		t.Fatalf("status = %q, want complete (any inbound ETH)", res.Status)
	}
	if res.Target.Mode != domain.ModeAny {
		t.Errorf("mode = %q, want any", res.Target.Mode)
	}
}

// ── --new without --wallet ⇒ usage error before any chain work ──

func TestReceive_New_WithoutWallet_Usage(t *testing.T) {
	f := fake.New()
	svc := receiveService(t, f, time.Second)
	_, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{New: true, Amount: "0.1"}, nil)
	if err == nil {
		t.Fatal("--new without --wallet must be a usage error")
	}
	if domain.AsError(err).Code != domain.CodeUsage+".new_needs_wallet" {
		t.Fatalf("error code = %q, want usage.new_needs_wallet", domain.AsError(err).Code)
	}
}

// ── --new on an empty/unwritable keystore must error, not block ──

func TestReceive_New_RequiresWritableKeystore(t *testing.T) {
	f := fake.New()
	svc := receiveService(t, f, time.Second)
	svc.secretIO = SecretIO{LookupEnv: func(k string) (string, bool) {
		if k == "DAXIE_PASSPHRASE" {
			return "p", true
		}
		return "", false
	}}
	_, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{New: true, Wallet: "treasury", Amount: "0.1", Timeout: domain.Duration{D: time.Second}}, nil)
	if err == nil {
		t.Fatal("--new on an empty/unwritable keystore must error, not block")
	}
}

// ── the poll loop BLOCKS through the injected Sleep at the configured poll
//    interval (issue #3: production must not busy-spin). A nil Options.Sleep falls
//    back to noDelaySleep and the loop spins; this asserts the loop actually calls
//    the injected sleeper with receive.poll-interval between polls, so the cli's
//    realSleeper injection is what gives a real `daxie receive` its 4s cadence. ──

func TestReceive_PollLoop_HonorsInjectedSleepAtPollInterval(t *testing.T) {
	isolate(t)
	listen := someAddr(1)
	f := fake.New()
	f.BlockNum = 5
	f.BlockByNumberFn = noTxBlocks()
	cc := &balanceClient{Client: f, balanceFn: func(_ *big.Int) *big.Int { return big.NewInt(0) }}

	// An unbounded listen (no --timeout) with no inbound NEVER completes — so if the
	// loop did not block through Sleep it would spin forever (the production bug). The
	// recording sleeper captures every duration the loop blocks on, then cancels the
	// context after the first few calls so the loop exits deterministically via ctx
	// (surfaced as a resumable timeout). This proves the loop blocks through the
	// injected Sleep at the configured poll interval rather than busy-spinning.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		mu        sync.Mutex
		sleepArgs []time.Duration
	)
	rec := func(c context.Context, d time.Duration) error {
		mu.Lock()
		sleepArgs = append(sleepArgs, d)
		n := len(sleepArgs)
		mu.Unlock()
		if n >= 3 {
			cancel() // exit the otherwise-unbounded loop deterministically
		}
		select {
		case <-c.Done():
			return c.Err()
		default:
			return nil
		}
	}
	svc, err := Open(context.Background(), Options{
		Clock: advancingClock(time.Date(2026, 6, 16, 17, 0, 0, 0, time.UTC), time.Second),
		Sleep: rec,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.chains = &stubProvider{cc: cc}

	cs := &collectSink{}
	// No --timeout ⇒ an unbounded invoice wait; only the Sleep-driven cancellation
	// ends it (a busy-spin would hang this test forever / never call Sleep).
	if _, rerr := svc.Receive(ctx, domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Amount: "1"}, cs.sink()); rerr != nil {
		t.Fatalf("Receive: %v", rerr)
	}

	mu.Lock()
	args := append([]time.Duration(nil), sleepArgs...)
	mu.Unlock()
	if len(args) == 0 {
		t.Fatal("the poll loop never blocked through the injected Sleep — it busy-spins (production CPU peg / RPC hammer)")
	}
	want := svc.cfg.Receive.PollInterval
	if want <= 0 {
		t.Fatalf("receive.poll-interval default is %v, want a positive cadence", want)
	}
	for i, d := range args {
		if d != want {
			t.Errorf("Sleep call %d = %v, want the configured poll interval %v", i, d, want)
		}
	}
}

// ── heartbeat fires in a quiet period ──

func TestReceive_Heartbeat_QuietPeriod(t *testing.T) {
	listen := someAddr(1)
	f := fake.New()
	f.BlockNum = 5
	f.BlockByNumberFn = noTxBlocks()
	cc := &balanceClient{Client: f, balanceFn: func(_ *big.Int) *big.Int { return big.NewInt(0) }}
	// A clock step of 40s crosses the 60s heartbeat interval within a couple loops;
	// a generous timeout lets the heartbeat fire before the deadline.
	svc := receiveService(t, cc, 40*time.Second)
	cs := &collectSink{}
	_, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Amount: "1", Timeout: domain.Duration{D: 5 * time.Minute}}, cs.sink())
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !cs.has(domain.EvHeartbeat) {
		t.Errorf("expected a heartbeat in the quiet period; stream = %v", cs.kinds())
	}
}
