// Package abi is the ABI codec + positional-string arg coercion + the calldata
// SELECTOR RECOGNIZERS (design §2.1, the contract-verb analogue of erc/ §2.8).
//
// It is a PURE PROVIDER LEAF. It imports only:
//
//   - internal/domain (the error taxonomy — usage.* codes the CLI projects to
//     exit 2);
//   - the Go standard library;
//   - go-ethereum value/behavioral packages: accounts/abi (the codec), common
//     (Address/Hash), crypto (keccak for selectors/topics), and math/big.
//
// It imports NO other internal package — never chain, service, a frontend,
// policy, or registry. The arch matrix's only inbound provider edge to abi is
// the sanctioned policy→abi edge (policy.ClassifyCalldata delegates selector
// matching to abi.ClassifySelector so the §4.2 known-selector set is defined
// ONCE and shared with `contract decode`/display). TestM10ContractFilesOnCorrectSide
// pins this leaf purity.
//
// CGO-free (J8/§9.4): keccak runs via go-ethereum crypto over golang.org/x/crypto
// (sha3), and the package touches NO secp256k1, so CGO_ENABLED=0 holds for the
// shipped binary exactly as it does for erc/.
//
// Codec is a stateless concrete struct (§2.1.1 deliberately rejects an interface:
// one impl, determinism a property of pure functions over bytes + types, golden-
// tested against cast-encoded bytes). A single zero value serves every request;
// service holds a bare abi.Codec.
//
// Three responsibilities, three files:
//
//   - abi.go     — ParseJSON, ParseSig, PackCall, UnpackReturns, UnpackCalldata,
//     PackEvent, UnpackLog, EventTopic0 (the codec).
//   - coerce.go  — CoerceArgs + ParseLiteral (the §2.5 "parse once" arg grammar:
//     scalars, large-uint, bracketed array/tuple literals, nesting,
//     double-quoted delimiter-bearing elements).
//   - classify.go — ClassifySelector (the §4.2 raw-calldata recognizer source).
//
// Anti-spoofing note (§4.2 line 1644): ClassifySelector matches on the leading
// 4-byte selector + a SUCCESSFUL ABI-decode of the argument shape, NEVER on a
// name string — the selector is a property of the SIGNED BYTES; a user-supplied
// ABI may lie. Classification reads the calldata bytes, not the ABI claims.
package abi
