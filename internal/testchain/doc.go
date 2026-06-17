// Package testchain is the anvil integration harness (design §2.9): it spawns a
// local anvil devnet and exposes its URL, chain-id, and funded/empty dev accounts
// so the real chain.Client adapter can be exercised against a real EVM.
//
// The harness itself lives in anvil.go behind //go:build integration so it (and
// its os/exec/net dependencies) compile only into the integration test binary
// (`go test -tags integration`). This doc.go carries the package clause with no
// build tag so the package always builds and classifies cleanly in the import
// matrix (internal/arch_test.go), even under a plain `go test ./...`.
//
// testchain is a provider-class leaf used only by integration tests; it imports
// internal/chain (to dial + satisfy chaintest.Harness) — a sanctioned
// testchain→chain edge. It NEVER imports service or a frontend.
package testchain
