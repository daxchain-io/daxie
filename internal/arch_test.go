// Package archtest enforces the one-core/two-frontends import matrix (design §2.2,
// §2.3c) as a REAL Go test, not a comment or a linter config. The depguard rules in
// .golangci.yml and the lattice in .go-arch-lint.yml are belt-and-suspenders; this
// test is the load-bearing gate: it goes red the moment the dependency law is broken,
// even with every linter uninstalled.
//
// How it works: it shells out to `go list -json ./...` (the same data the Go
// toolchain uses), reads each module package's DIRECT imports (the Imports /
// TestImports fields — not the transitive closure, so the assertions catch the
// *authored* edge, and viper-via-config does not falsely implicate every package),
// classifies each package into an architectural layer by its import path, and
// asserts every edge against the allow-matrix below.
//
// Example violations this test CATCHES (each would turn the test red):
//
//   - `internal/cli/convert.go` does `import ".../internal/config"`  — a FRONTEND
//     reaching a PROVIDER. Frontends may import service+domain+version+ethunit only.
//   - `internal/chain/dial.go` does `import ".../internal/service"`   — a PROVIDER
//     importing the CORE. Providers are leaves; the core composes them, never the
//     reverse.
//   - `internal/domain/amount.go` does `import ".../internal/ethunit"` — the
//     CONTRACT importing something internal. domain imports nothing internal.
//   - any package outside `internal/config` doing `import "github.com/spf13/viper"`
//     — Viper is allow-listed to config only (§2.2 rule 5).
//   - `internal/ens/x.go` doing `import ".../internal/journal"` — an un-sanctioned
//     provider→provider edge (only the §2.2 allow-list edges are permitted).
package archtest

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePrefix = "github.com/daxchain-io/daxie"
const internalPrefix = modulePrefix + "/internal/"

// goListPackage is the subset of `go list -json` output this test consumes.
type goListPackage struct {
	ImportPath  string   `json:"ImportPath"`
	Imports     []string `json:"Imports"`     // direct imports of the package's non-test files
	TestImports []string `json:"TestImports"` // direct imports of in-package _test.go files
}

// layer is an architectural class. A package belongs to exactly one layer; an import
// path that matches none is treated as external/stdlib and never constrains an edge
// (the matrix only governs internal-to-internal and the viper carve-out).
type layer int

const (
	layerExternal layer = iota // stdlib or third-party; not classified
	layerHost                  // cmd/daxie
	layerFrontend              // internal/cli, internal/cli/render, internal/mcpserver, internal/mcpserver/tools
	layerCore                  // internal/service
	layerContract              // internal/domain
	layerProvider              // every internal leaf (config, chain, fsx, ...)
	layerVersion               // internal/version
)

func (l layer) String() string {
	switch l {
	case layerHost:
		return "host"
	case layerFrontend:
		return "frontend"
	case layerCore:
		return "core"
	case layerContract:
		return "contract"
	case layerProvider:
		return "provider"
	case layerVersion:
		return "version"
	default:
		return "external"
	}
}

// providerNames is the full set of provider package names (design §2.1/§2.2),
// including ones not yet authored in M0 — naming them now means a future add cannot
// land on the wrong side of the matrix silently.
var providerNames = map[string]bool{
	"keys": true, "chain": true, "erc": true, "ens": true,
	"policy": true, "policyseal": true, "journal": true, "registry": true,
	"config": true, "secret": true, "fsx": true, "ethunit": true, "abi": true,
	// testchain (M2): the anvil integration harness (//go:build integration). It is
	// a provider-class leaf used only by integration tests; registering it here
	// keeps TestNoUnclassifiedInternalPackages from going red and governs its edges
	// (testchain→chain is sanctioned below).
	"testchain": true,
}

// frontendRoots are the package-path leaders (relative to internalPrefix) that mark a
// frontend. Anything under these prefixes is a frontend (so cli/render counts too).
var frontendRoots = []string{"cli", "mcpserver"}

// classify maps a full import path to its architectural layer.
func classify(importPath string) layer {
	if importPath == modulePrefix+"/cmd/daxie" {
		return layerHost
	}
	if !strings.HasPrefix(importPath, internalPrefix) {
		return layerExternal
	}
	rel := strings.TrimPrefix(importPath, internalPrefix) // e.g. "cli/render", "service", "domain"
	first := rel
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		first = rel[:i]
	}
	switch first {
	case "version":
		return layerVersion
	case "service":
		return layerCore
	case "domain":
		return layerContract
	}
	for _, fr := range frontendRoots {
		if first == fr {
			return layerFrontend
		}
	}
	if providerNames[first] {
		return layerProvider
	}
	// An unknown internal package is a hard signal the matrix is out of date.
	return layerExternal
}

// providerOf returns the provider's short name (e.g. "chain") for a provider import
// path, used to check the sanctioned provider→provider edge allow-list.
func providerOf(importPath string) string {
	rel := strings.TrimPrefix(importPath, internalPrefix)
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		return rel[:i]
	}
	return rel
}

// sanctionedProviderEdges is the EXACT allow-list of provider→provider imports
// (design §2.2). Any provider→provider edge not in this set fails the test.
// Keyed "from→to".
var sanctionedProviderEdges = map[string]bool{
	"ens→chain":         true,
	"erc→chain":         true,
	"policy→policyseal": true,
	"policy→abi":        true,
	// {config,keys,journal,policy,registry,chain} → fsx
	// chain→fsx (M2): chain.Dial perms-checks the mTLS client-key file with
	// fsx.CheckPerms before loading it (§7.5 — the key file is permission-checked
	// like a passphrase file). This is the only provider→provider edge M2 adds.
	"config→fsx": true, "keys→fsx": true, "journal→fsx": true,
	"policy→fsx": true, "registry→fsx": true, "chain→fsx": true,
	// testchain→chain (M2): the anvil integration harness dials the real adapter
	// and implements chaintest.Harness; both targets classify as the "chain"
	// provider. Test-only (//go:build integration).
	"testchain→chain": true,
	// {config,keys,journal,policy,registry} → secret
	"config→secret": true, "keys→secret": true, "journal→secret": true,
	"policy→secret": true, "registry→secret": true,
}

func TestImportMatrix(t *testing.T) {
	pkgs := goListAll(t)

	for _, p := range pkgs {
		from := classify(p.ImportPath)
		if from == layerExternal {
			continue // not one of our governed packages
		}
		for _, imp := range p.Imports {
			checkEdge(t, p.ImportPath, from, imp)
		}
	}
}

// checkEdge asserts a single from→imp edge is permitted by the matrix.
func checkEdge(t *testing.T, fromPath string, from layer, imp string) {
	t.Helper()

	// The Viper carve-out (§2.2 rule 5): allowed only inside config.
	if imp == "github.com/spf13/viper" {
		if classify(fromPath) != layerProvider || providerOf(fromPath) != "config" {
			t.Errorf("VIPER LEAK: %s imports github.com/spf13/viper; viper is allow-listed to internal/config only", fromPath)
		}
		return
	}

	// geth behavioral packages are banned from domain (§2.2 rule 3).
	if from == layerContract && isGethBehavioral(imp) {
		t.Errorf("CONTRACT VIOLATION: %s (domain) imports geth behavioral package %q; domain may use geth VALUE types only", fromPath, imp)
		return
	}

	to := classify(imp)
	if to == layerExternal {
		return // stdlib / third-party: not governed by the internal matrix
	}

	switch from {
	case layerHost:
		// cmd/daxie may import cli + version only.
		if to != layerFrontend && to != layerVersion {
			t.Errorf("HOST VIOLATION: %s imports %s (%s); cmd/daxie may import cli + version only", fromPath, imp, to)
		}
		// And only the cli frontend, not mcpserver directly (host calls cli.Execute).
		if to == layerFrontend && providerOf(imp) != "cli" {
			t.Errorf("HOST VIOLATION: %s imports %s; cmd/daxie may import internal/cli only (not %s)", fromPath, imp, imp)
		}

	case layerFrontend:
		switch to {
		case layerCore, layerContract, layerVersion:
			// allowed
		case layerFrontend:
			// cli→mcpserver is the single sanctioned cross-frontend wiring edge (M11).
		case layerProvider:
			// Only ethunit is permitted to a frontend (output formatting, §2.2 row).
			if providerOf(imp) != "ethunit" {
				t.Errorf("FRONTEND VIOLATION: %s imports provider %s; frontends import service+domain(+version,+ethunit) only", fromPath, imp)
			}
		default:
			t.Errorf("FRONTEND VIOLATION: %s imports %s (%s); frontends import service+domain(+version,+ethunit) only", fromPath, imp, to)
		}

	case layerCore:
		// service may import domain + every provider; never a frontend.
		if to == layerFrontend {
			t.Errorf("CORE VIOLATION: %s (service) imports frontend %s; the core never imports a frontend", fromPath, imp)
		}

	case layerContract:
		// domain imports nothing internal.
		if to != layerExternal {
			t.Errorf("CONTRACT VIOLATION: %s (domain) imports internal package %s; domain imports nothing internal", fromPath, imp)
		}

	case layerProvider:
		switch to {
		case layerCore:
			t.Errorf("PROVIDER VIOLATION: %s imports service; providers are leaves and never import the core", fromPath)
		case layerFrontend:
			t.Errorf("PROVIDER VIOLATION: %s imports frontend %s; providers never import a frontend", fromPath, imp)
		case layerProvider:
			edge := providerOf(fromPath) + "→" + providerOf(imp)
			if providerOf(fromPath) != providerOf(imp) && !sanctionedProviderEdges[edge] {
				t.Errorf("PROVIDER VIOLATION: un-sanctioned provider→provider edge %q (%s imports %s); only the §2.2 allow-list edges are permitted", edge, fromPath, imp)
			}
		case layerContract, layerVersion:
			// providers may import domain (errors/types); version is harmless.
		}

	case layerVersion:
		if to != layerExternal {
			t.Errorf("VERSION VIOLATION: %s imports internal package %s; version imports nothing internal", fromPath, imp)
		}
	}
}

// TestNoUnclassifiedInternalPackages closes the silent-un-governance gap: classify()
// returns layerExternal for an internal path it does not recognize, and
// TestImportMatrix skips every layerExternal source — so a brand-new internal package
// (not in providerNames/frontendRoots and not under version/service/domain) would land
// with ZERO import-matrix enforcement, as both a source AND a target of edges. This
// test makes that a HARD failure: every package under internalPrefix MUST classify to a
// governed layer. Whoever adds internal/foo is forced to register it in
// providerNames/frontendRoots (and the depguard + go-arch-lint lattices) or this test
// goes red — restoring the stated guarantee that "a future add cannot land on the wrong
// side of the matrix silently."
func TestNoUnclassifiedInternalPackages(t *testing.T) {
	for _, p := range goListAll(t) {
		// Only the module's own internal packages are subject to classification;
		// cmd/daxie is the host and classifies explicitly.
		if !strings.HasPrefix(p.ImportPath, internalPrefix) {
			continue
		}
		if classify(p.ImportPath) == layerExternal {
			t.Errorf("UNCLASSIFIED INTERNAL PACKAGE: %s classifies to layerExternal and is therefore ungoverned by the import matrix; register it in providerNames or frontendRoots (and the depguard + go-arch-lint lattices) so it lands on the correct side of the matrix", p.ImportPath)
		}
	}
}

// TestProviderConcreteness enforces the §2.1.1/§2.8 rule that the per-request
// endpoint-binding providers (`ens.Resolver`, `erc.Ops`) are CONCRETE structs that
// take a chain.Client PER CALL, NOT interfaces. §2.1.1 rejects an ens.Resolver
// interface explicitly: the single load-bearing chain seam is the chain.Client fake
// one layer down, so adding an ens.Resolver interface would invent a second,
// redundant mock surface (and tempt a stateful resolver). The ENS pin-refusal test
// proves drift via the chain.Client fake returning X then Y — never via an
// ens.Resolver mock. This AST guard goes red the moment someone turns either named
// type into an interface.
//
// It asserts, per provider package: the named type (Resolver / Ops) is declared as a
// struct, and NO interface type of that name exists. A missing package is skipped
// (the guard engages once the milestone authors the type) so it never fails an
// earlier-milestone build.
func TestProviderConcreteness(t *testing.T) {
	root := moduleRoot(t)
	cases := []struct {
		pkgRel   string // internal-relative dir
		typeName string // the concrete type that must be a struct, never an interface
	}{
		{"internal/ens", "Resolver"}, // §2.8: ens.Resolver is a concrete struct, chain.Client per call
		{"internal/erc", "Ops"},      // §2.8: erc.Ops is a concrete struct, chain.Client per call
	}
	for _, c := range cases {
		dir := filepath.Join(root, c.pkgRel)
		if _, err := os.Stat(dir); err != nil {
			t.Logf("provider package %s not present yet; concreteness guard idle but active", c.pkgRel)
			continue
		}
		kind, found := namedTypeKind(t, dir, c.typeName)
		if !found {
			t.Errorf("CONCRETENESS: %s declares no type %q — the §2.8 per-call provider type is missing", c.pkgRel, c.typeName)
			continue
		}
		switch kind {
		case typeKindStruct:
			// correct: a concrete struct
		case typeKindInterface:
			t.Errorf("CONCRETENESS VIOLATION: %s.%s is declared as an INTERFACE; §2.1.1/§2.8 require a CONCRETE struct taking chain.Client per call (the test seam is the chain.Client fake one layer down, NOT a provider-interface mock)", c.pkgRel, c.typeName)
		default:
			t.Errorf("CONCRETENESS: %s.%s is neither a struct nor an interface; §2.8 expects a concrete struct", c.pkgRel, c.typeName)
		}
	}
}

type namedTypeKindEnum int

const (
	typeKindOther namedTypeKindEnum = iota
	typeKindStruct
	typeKindInterface
)

// namedTypeKind parses every non-test .go file in dir and reports the declared kind
// (struct / interface / other) of the top-level type named `name`. found=false when
// no such type is declared in the package.
func namedTypeKind(t *testing.T, dir, name string) (namedTypeKindEnum, bool) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		fn := e.Name()
		if e.IsDir() || !strings.HasSuffix(fn, ".go") || strings.HasSuffix(fn, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, fn), nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parsing %s: %v", fn, perr)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name == nil || ts.Name.Name != name {
					continue
				}
				switch ts.Type.(type) {
				case *ast.StructType:
					return typeKindStruct, true
				case *ast.InterfaceType:
					return typeKindInterface, true
				default:
					return typeKindOther, true
				}
			}
		}
	}
	return typeKindOther, false
}

// TestM8ReceiveFilesOnCorrectSide pins the M8 `daxie receive` files explicitly onto
// the right side of the import matrix (design §2.2/§2.3c), per-FILE rather than
// per-package, so a future edit that, say, makes the cli receive command reach a
// provider (the chain client, keys, erc) to "just fetch one log" goes red here even
// if the package as a whole still has a legitimate provider import via another file.
//
//   - cli/receive.go + cli/render/receive.go are FRONTEND files: they may import
//     service + domain + render + cobra (+ ethunit for output) — never a provider.
//   - service/receive.go + service/receive_eth.go are CORE files: they may import
//     domain + providers (chain/erc/ens/registry/keys/ethunit/…) — never a frontend.
//
// The package-level TestImportMatrix already enforces the same law; this adds a
// load-bearing file-scoped regression guard for the engine/frontend split that M8
// introduces (the engine must stay in the core, the command a thin host).
func TestM8ReceiveFilesOnCorrectSide(t *testing.T) {
	root := moduleRoot(t)
	cases := []struct {
		file       string // module-relative path
		wantLayer  layer
		bannedDesc string
	}{
		{"internal/cli/receive.go", layerFrontend, "a provider (the receive command is a thin host; the engine lives in the core)"},
		{"internal/cli/render/receive.go", layerFrontend, "a provider (the NDJSON renderer formats only; it imports domain, never a provider)"},
		{"internal/service/receive.go", layerCore, "a frontend (the detection engine is core; it never imports cli/render)"},
		{"internal/service/receive_eth.go", layerCore, "a frontend (the balance-delta math is core; it never imports cli/render)"},
	}
	for _, c := range cases {
		path := filepath.Join(root, c.file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("M8 file %s is missing: %v", c.file, err)
			continue
		}
		for _, imp := range fileImports(t, path) {
			to := classify(imp)
			switch c.wantLayer {
			case layerFrontend:
				// A frontend file may not import a provider (ethunit excepted for output).
				if to == layerProvider && providerOf(imp) != "ethunit" {
					t.Errorf("M8 FRONTEND VIOLATION: %s imports provider %s; it must reach %s", c.file, imp, c.bannedDesc)
				}
				if to == layerHost {
					t.Errorf("M8 FRONTEND VIOLATION: %s imports the host %s", c.file, imp)
				}
			case layerCore:
				// A core file may not import a frontend.
				if to == layerFrontend {
					t.Errorf("M8 CORE VIOLATION: %s imports frontend %s; it must not reach %s", c.file, imp, c.bannedDesc)
				}
			}
		}
	}
}

// TestM9SignFilesOnCorrectSide pins the M9 `daxie sign` / `daxie verify` files
// explicitly onto the right side of the import matrix (design §2.2/§2.3c), per-FILE
// rather than per-package, so a future edit that, say, makes the sign command reach a
// provider (the keys backend, the policy engine) to "just classify one permit" goes
// red here even if the package as a whole still has a legitimate provider import via
// another file. The §2.7 authorizeSignature gate + the EIP-712 hashing + ecrecover
// MUST stay in the core (the privileged sequence runs ahead of domain.Signer, behind
// the service boundary frontends cannot cross); the commands stay thin hosts.
//
//   - cli/sign.go + cli/verify.go + cli/render/sign.go are FRONTEND files: they may
//     import service + domain + render + cobra (+ ethunit for output) — never a
//     provider (not policy, not keys, not chain). The geth common/apitypes/crypto
//     value packages are external (stdlib-class to the matrix), so a frontend reading
//     common.IsHexAddress for a flag check is fine; reaching internal/policy is not.
//   - service/sign.go + service/verify.go are CORE files: they may import domain +
//     providers (policy/keys/chain/ens/ethunit/…) — never a frontend (cli/render).
//
// The package-level TestImportMatrix already enforces the same law; this adds a
// load-bearing file-scoped regression guard for the gasless-signing engine/frontend
// split that M9 introduces.
func TestM9SignFilesOnCorrectSide(t *testing.T) {
	root := moduleRoot(t)
	cases := []struct {
		file       string // module-relative path
		wantLayer  layer
		bannedDesc string
	}{
		{"internal/cli/sign.go", layerFrontend, "a provider (the sign command is a thin host; authorizeSignature + EIP-712 hashing live in the core)"},
		{"internal/cli/verify.go", layerFrontend, "a provider (the verify command is a thin host; ecrecover + ENS resolution live in the core)"},
		{"internal/cli/render/sign.go", layerFrontend, "a provider (the sign/verify renderers format only; they import domain, never a provider)"},
		{"internal/service/sign.go", layerCore, "a frontend (the §2.7 authorizeSignature gate is core; it never imports cli/render)"},
		{"internal/service/verify.go", layerCore, "a frontend (the ecrecover verify path is core; it never imports cli/render)"},
	}
	for _, c := range cases {
		path := filepath.Join(root, c.file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("M9 file %s is missing: %v", c.file, err)
			continue
		}
		for _, imp := range fileImports(t, path) {
			to := classify(imp)
			switch c.wantLayer {
			case layerFrontend:
				if to == layerProvider && providerOf(imp) != "ethunit" {
					t.Errorf("M9 FRONTEND VIOLATION: %s imports provider %s; it must reach %s", c.file, imp, c.bannedDesc)
				}
				if to == layerHost {
					t.Errorf("M9 FRONTEND VIOLATION: %s imports the host %s", c.file, imp)
				}
			case layerCore:
				if to == layerFrontend {
					t.Errorf("M9 CORE VIOLATION: %s imports frontend %s; it must not reach %s", c.file, imp, c.bannedDesc)
				}
			}
		}
	}
}

// TestM10ContractFilesOnCorrectSide pins the M10 `daxie contract` files explicitly onto
// the right side of the import matrix (design §2.2/§2.3c), per-FILE rather than per-
// package, so a future edit that, say, makes the contract command reach a provider (the
// chain client, the abi codec, the policy engine) to "just classify one selector" goes
// red here even if the package as a whole still has a legitimate provider import via
// another file. The §4.2 ClassifyCalldata + the §5.1 authorize kernel + the §5.11 read
// paths MUST stay in the core; the command stays a thin host.
//
//   - cli/contract.go + cli/render/contract.go are FRONTEND files: they may import
//     service + domain + render + cobra (+ ethunit for output) — never a provider (not
//     abi, not chain, not policy, not registry). The geth common/abi value packages are
//     external (stdlib-class to the matrix), so a frontend reading a value type for a
//     flag check is fine; reaching internal/abi or internal/policy is not.
//   - service/contract.go is a CORE file: it may import domain + providers (abi/chain/
//     registry/policy/journal/ethunit/…) — never a frontend (cli/render).
//
// It ALSO pins the §2.2 "abi is a pure leaf" claim: every internal/abi/*.go file may
// import internal/domain (errors) ONLY — NO other internal package. A future edit that
// reaches chain/policy/registry from abi (which would let the codec do I/O or know about
// policy) goes red here. The package-level TestImportMatrix already classifies abi as a
// provider and validates policy→abi is the only inbound provider edge; this adds the
// stricter per-file leaf-purity + the per-file frontend/core split.
func TestM10ContractFilesOnCorrectSide(t *testing.T) {
	root := moduleRoot(t)
	cases := []struct {
		file       string // module-relative path
		wantLayer  layer
		bannedDesc string
	}{
		{"internal/cli/contract.go", layerFrontend, "a provider (the contract command is a thin host; ClassifyCalldata + the authorize kernel live in the core)"},
		{"internal/cli/render/contract.go", layerFrontend, "a provider (the contract renderers format only; they import domain, never a provider)"},
		{"internal/service/contract.go", layerCore, "a frontend (the contract use cases are core; they never import cli/render)"},
	}
	for _, c := range cases {
		path := filepath.Join(root, c.file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("M10 file %s is missing: %v", c.file, err)
			continue
		}
		for _, imp := range fileImports(t, path) {
			to := classify(imp)
			switch c.wantLayer {
			case layerFrontend:
				if to == layerProvider && providerOf(imp) != "ethunit" {
					t.Errorf("M10 FRONTEND VIOLATION: %s imports provider %s; it must reach %s", c.file, imp, c.bannedDesc)
				}
				if to == layerHost {
					t.Errorf("M10 FRONTEND VIOLATION: %s imports the host %s", c.file, imp)
				}
			case layerCore:
				if to == layerFrontend {
					t.Errorf("M10 CORE VIOLATION: %s imports frontend %s; it must not reach %s", c.file, imp, c.bannedDesc)
				}
			}
		}
	}

	// internal/abi leaf-purity: every abi source file imports internal/domain ONLY (of
	// the module's own internal packages). The codec is a pure provider leaf (geth value
	// packages + stdlib + domain errors); reaching any other internal package would let
	// it do I/O or know about policy/chain — the §2.2 "abi is a pure leaf" invariant.
	abiDir := filepath.Join(root, "internal/abi")
	if _, err := os.Stat(abiDir); err != nil {
		t.Errorf("M10: internal/abi is missing: %v", err)
		return
	}
	entries, err := os.ReadDir(abiDir)
	if err != nil {
		t.Fatalf("reading internal/abi: %v", err)
	}
	for _, e := range entries {
		fn := e.Name()
		if e.IsDir() || !strings.HasSuffix(fn, ".go") || strings.HasSuffix(fn, "_test.go") {
			continue
		}
		for _, imp := range fileImports(t, filepath.Join(abiDir, fn)) {
			if !strings.HasPrefix(imp, internalPrefix) {
				continue // stdlib / geth / external — fine for a leaf
			}
			if imp != modulePrefix+"/internal/domain" {
				t.Errorf("ABI LEAF-PURITY VIOLATION: internal/abi/%s imports %s; the abi codec is a pure leaf and may import internal/domain ONLY (§2.2)", fn, imp)
			}
		}
	}
}

// fileImports parses one Go file and returns its direct import paths (unquoted).
func fileImports(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	out := make([]string, 0, len(f.Imports))
	for _, spec := range f.Imports {
		out = append(out, strings.Trim(spec.Path.Value, `"`))
	}
	return out
}

// TestNoViperOutsideConfigInTests guards the test code too: a _test.go file anywhere
// but config that pulls viper would still constitute a leak in the built test binary.
func TestNoViperOutsideConfigInTests(t *testing.T) {
	for _, p := range goListAll(t) {
		from := classify(p.ImportPath)
		if from == layerExternal {
			continue
		}
		for _, imp := range p.TestImports {
			if imp == "github.com/spf13/viper" {
				if from != layerProvider || providerOf(p.ImportPath) != "config" {
					t.Errorf("VIPER LEAK (test): %s test imports viper; allow-listed to internal/config only", p.ImportPath)
				}
			}
		}
	}
}

func isGethBehavioral(imp string) bool {
	const gethPrefix = "github.com/ethereum/go-ethereum/"
	if !strings.HasPrefix(imp, gethPrefix) {
		return false
	}
	rel := strings.TrimPrefix(imp, gethPrefix)
	// Behavioral subtrees banned from domain; value-type packages (common, params,
	// core/types, signer/core/apitypes) are permitted.
	for _, banned := range []string{"ethclient", "rpc", "accounts", "les", "p2p", "node", "eth/", "internal/ethapi"} {
		if rel == strings.TrimSuffix(banned, "/") || strings.HasPrefix(rel, banned) {
			return true
		}
	}
	return false
}

// goListAll runs `go list -json ./...` and returns every package in this module
// (no -deps: we assert on the module's own packages and their DIRECT imports;
// classify() gates so external import targets never constrain an edge).
func goListAll(t *testing.T) []goListPackage {
	t.Helper()
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = moduleRoot(t)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list failed: %v\nstderr:\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list failed: %v", err)
	}
	var pkgs []goListPackage
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p goListPackage
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatal("go list returned no packages")
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].ImportPath < pkgs[j].ImportPath })
	return pkgs
}

// moduleRoot returns the module root by asking the toolchain, so the test runs
// correctly regardless of which package directory `go test` invokes it from.
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", modulePrefix).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("locating module root: %v\nstderr:\n%s", err, ee.Stderr)
		}
		t.Fatalf("locating module root: %v", err)
	}
	return strings.TrimSpace(string(out))
}
