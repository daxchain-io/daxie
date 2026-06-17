package chain_test

import (
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/chaintest"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/ethereum/go-ethereum/common"
)

// fakeHarness adapts a programmed fake to the chaintest.Harness so the SHARED
// contract suite runs against the fake exactly as it runs against the real
// adapter at anvil — this is the §2.9 anti-drift guarantee in action.
type fakeHarness struct {
	chainID   *big.Int
	funded    common.Address
	fundedWei *big.Int
	empty     common.Address
	subscribe bool
}

func (h fakeHarness) ExpectChainID() *big.Int       { return h.chainID }
func (h fakeHarness) FundedAddress() common.Address { return h.funded }
func (h fakeHarness) ExpectFundedWei() *big.Int     { return h.fundedWei }
func (h fakeHarness) EmptyAddress() common.Address  { return h.empty }
func (h fakeHarness) SupportsSubscribe() bool       { return h.subscribe }

// newProgrammedFake builds a fake + matching harness with one funded and one
// empty address, on the given chain-id, with the given subscribe semantics.
func newProgrammedFake(chainID int64, subscribe bool) (*fake.Client, fakeHarness) {
	funded := common.HexToAddress("0x1111111111111111111111111111111111111111")
	empty := common.HexToAddress("0x2222222222222222222222222222222222222222")
	fundedWei := big.NewInt(1_000_000_000_000_000_000) // 1 ETH

	c := fake.New()
	c.ChainIDVal = big.NewInt(chainID)
	c.Balances[funded] = new(big.Int).Set(fundedWei)
	// empty is left out of the map => zero balance by contract.
	c.SupportsSubscribe = subscribe

	return c, fakeHarness{
		chainID:   big.NewInt(chainID),
		funded:    funded,
		fundedWei: fundedWei,
		empty:     empty,
		subscribe: subscribe,
	}
}

// TestContractSuite_FakeHTTP runs the shared contract suite against the fake in
// HTTP mode (Subscribe* → ErrNotSupported), the same suite the real adapter runs
// at anvil. If the fake ever drifts from the contract, this goes red.
func TestContractSuite_FakeHTTP(t *testing.T) {
	chaintest.Run(t, func(t *testing.T) (chain.Client, chaintest.Harness) {
		c, h := newProgrammedFake(1, false)
		return c, h
	})
}

// TestContractSuite_FakeWebsocket runs the shared suite against the fake in
// websocket mode (Subscribe* live), exercising the subscribe-capable branch of
// the contract.
func TestContractSuite_FakeWebsocket(t *testing.T) {
	chaintest.Run(t, func(t *testing.T) (chain.Client, chaintest.Harness) {
		c, h := newProgrammedFake(11155111, true)
		return c, h
	})
}
