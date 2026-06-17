package mcpserver

import "github.com/daxchain-io/daxie/internal/mcpserver/tools"

// errors.go re-exposes the design §6.6 error-mapping helpers under the mcpserver
// core package, forwarding to the SINGLE implementation in mcpserver/tools (the
// only cycle-free direction, since mcpserver imports tools for Register). There is
// exactly one §6.6 taxonomy projection — the lowercase impls in tools — and these
// are thin forwards so the core and its tools subpackage cannot drift.
//
//	toolError   — a *domain.Error passes straight through; a raw error → {internal};
//	              nil → nil (the success path). The SDK packs the result into the
//	              tool-error envelope (IsError) byte-identical to the CLI --json error.
//	dualSignal  — true for the tx.reverted / tx.wait_timeout / tx.nonce_gap codes
//	              that need BOTH IsError:true AND the structured *domain.TxResult.

func toolError(err error) error { return tools.ToolError(err) }
func dualSignal(err error) bool { return tools.DualSignal(err) }
