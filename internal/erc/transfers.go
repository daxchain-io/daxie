package erc

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Transfer is one decoded ERC-20 Transfer log. Token is the emitting contract
// (log.Address); From/To are the indexed parties; Value is the base-unit amount
// (the non-indexed data word). The M8 receive engine is the consumer; defined now
// per §2.8 and tested with the golden ParseTransfers vector.
type Transfer struct {
	Token common.Address
	From  common.Address
	To    common.Address
	Value *big.Int
}

// transferTopic0 is keccak256("Transfer(address,address,uint256)") — the topic[0]
// signature hash every conforming ERC-20 Transfer event carries. Computed once at
// init from the canonical signature (not a hard-coded constant) so it cannot drift
// from the signature string; the test independently asserts its well-known value
// 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
var transferTopic0 = common.BytesToHash(keccak256Sig("Transfer(address,address,uint256)"))

// ParseTransfers decodes the ERC-20 Transfer(address indexed from,address indexed
// to,uint256 value) logs from a slice (e.g. an eth_getLogs / receipt result). It
// is TOLERANT: a log whose topic[0] is not the Transfer signature, or that is
// malformed for an ERC-20 Transfer (wrong topic count, short data, removed by a
// reorg), is SKIPPED rather than failing the whole batch — a receipt or block
// range carries many unrelated logs, and the receive engine wants the ERC-20
// transfers among them, not an error on the first non-Transfer log.
//
// An ERC-20 Transfer has exactly 3 topics (sig + indexed from + indexed to) and a
// 32-byte data word (the value). A would-be Transfer with the right topic[0] but
// the wrong shape is treated as malformed and skipped (ERC-721 Transfer shares the
// signature/topic[0] but indexes the tokenId as a THIRD indexed topic, so it has 4
// topics and empty data — it is correctly skipped here; ERC-721 is M6).
//
// The returned slice is never nil for a non-empty input that yields matches; an
// input with no ERC-20 Transfers yields a nil slice and a nil error. The function
// never returns a non-nil error in M5 (it cannot fail given a well-typed []Log);
// the error is in the signature per §2.8 for forward compatibility with stricter
// future decoding.
func (Ops) ParseTransfers(logs []types.Log) ([]Transfer, error) {
	var out []Transfer
	for i := range logs {
		t, ok := decodeTransferLog(logs[i])
		if !ok {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// decodeTransferLog decodes a single log as an ERC-20 Transfer, returning ok=false
// for anything that is not a well-formed ERC-20 Transfer (so the caller skips it).
func decodeTransferLog(l types.Log) (Transfer, bool) {
	// Reorg-removed logs are not real transfers.
	if l.Removed {
		return Transfer{}, false
	}
	// Exactly: topic0 = Transfer sig, topic1 = from, topic2 = to.
	if len(l.Topics) != 3 || l.Topics[0] != transferTopic0 {
		return Transfer{}, false
	}
	// The value is a single 32-byte non-indexed data word. (Extra trailing bytes
	// would be non-conforming; require exactly one word.)
	if len(l.Data) != 32 {
		return Transfer{}, false
	}
	return Transfer{
		Token: l.Address,
		From:  common.BytesToAddress(l.Topics[1].Bytes()),
		To:    common.BytesToAddress(l.Topics[2].Bytes()),
		Value: new(big.Int).SetBytes(l.Data),
	}, true
}
