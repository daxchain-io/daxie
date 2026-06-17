package chain

import (
	"context"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// newHeadHeightSub adapts a go-ethereum *types.Header subscription into a
// height-only (uint64) subscription that matches Client.SubscribeNewHead. It
// forwards each new header's block number onto out, and unsubscribes the
// upstream header subscription when the returned subscription is unsubscribed,
// when the upstream errors, or when ctx is cancelled — so there is no goroutine
// or upstream-subscription leak.
//
// The returned subscription's Err channel mirrors the upstream error (the single
// value go-ethereum guarantees), so callers see transport drops exactly as they
// would on a raw header subscription.
func newHeadHeightSub(
	ctx context.Context,
	upstream ethereum.Subscription,
	headers <-chan *types.Header,
	out chan<- uint64,
) ethereum.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer upstream.Unsubscribe()
		for {
			select {
			case h := <-headers:
				if h == nil || h.Number == nil {
					continue
				}
				select {
				case out <- h.Number.Uint64():
				case <-quit:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			case err := <-upstream.Err():
				return err
			case <-quit:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
}
