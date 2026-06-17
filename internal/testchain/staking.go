//go:build integration

package testchain

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// staking.go deploys the minimal test Staking fixture (stakingbytecode.go) to anvil and
// exposes the helpers the M10 `daxie contract` integration tests need: the deploy, the
// canonical ABI JSON the test registers via `contract add`, and a raw-RPC earned()
// reader (independent of Daxie's own abi/erc packages — no self-confirmation). Compiled
// only under `go test -tags integration`. It mirrors erc20.go.
//
// The standalone Solidity source (compiled offline into stakingbytecode.go):
//
//	// SPDX-License-Identifier: MIT
//	pragma solidity ^0.8.20;
//	contract Staking {
//	    mapping(address => uint256) public staked;
//	    mapping(address => uint256) public rewards;
//	    event Staked(address indexed user, uint256 amount);
//	    event Withdrawn(address indexed user, uint256 amount);
//	    event RewardPaid(address indexed user, uint256 reward);
//	    function stake(uint256 amount) external {
//	        staked[msg.sender] += amount;
//	        rewards[msg.sender] += amount / 10;
//	        emit Staked(msg.sender, amount);
//	    }
//	    function withdraw(uint256 amount) external {
//	        require(staked[msg.sender] >= amount, "insufficient");
//	        staked[msg.sender] -= amount;
//	        emit Withdrawn(msg.sender, amount);
//	    }
//	    function getReward() external {
//	        uint256 r = rewards[msg.sender];
//	        rewards[msg.sender] = 0;
//	        emit RewardPaid(msg.sender, r);
//	    }
//	    function earned(address account) external view returns (uint256) {
//	        return rewards[account];
//	    }
//	}

// StakingABI is the canonical Solidity ABI JSON array for the Staking fixture — the
// exact bytes the integration test stores via `daxie contract add --abi-stdin`. It is
// also the --abi/--sig source for the ad-hoc-ABI scenarios.
const StakingABI = `[{"type":"function","name":"earned","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},{"type":"function","name":"getReward","inputs":[],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"stake","inputs":[{"name":"amount","type":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"withdraw","inputs":[{"name":"amount","type":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"event","name":"Staked","inputs":[{"name":"user","type":"address","indexed":true},{"name":"amount","type":"uint256","indexed":false}],"anonymous":false},{"type":"event","name":"Withdrawn","inputs":[{"name":"user","type":"address","indexed":true},{"name":"amount","type":"uint256","indexed":false}],"anonymous":false}]`

// itSelEarned is the earned(address) read selector, pinned so the raw reader is
// independent of any Daxie package.
var itSelEarned = []byte{0x00, 0x8c, 0xc2, 0x62} // earned(address)

// DeployStaking deploys the test Staking contract from anvil's unlocked dev account 0,
// waits for the receipt, and returns the deployed address. Mirrors DeployERC20.
func DeployStaking(t *testing.T, a *Anvil) common.Address {
	t.Helper()
	params := []any{map[string]any{
		"from": fundedAddr0.Hex(),
		"data": stakingBytecodeHex,
		"gas":  "0x" + big.NewInt(3_000_000).Text(16),
	}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("staking deploy tx hash decode: %v", err)
	}
	rcpt := a.waitReceipt(t, hash)
	addrStr, _ := rcpt["contractAddress"].(string)
	if addrStr == "" || !common.IsHexAddress(addrStr) {
		t.Fatalf("staking deploy receipt has no contractAddress: %+v", rcpt)
	}
	return common.HexToAddress(addrStr)
}

// StakingEarned reads earned(account) for the staking contract via a raw eth_call
// (independent of Daxie's abi package). It returns the accrued reward (base units).
func (a *Anvil) StakingEarned(t *testing.T, staking, account common.Address) *big.Int {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(itSelEarned, common.LeftPadBytes(account.Bytes(), 32)...))
	return a.ethCallUint(t, staking, data)
}
