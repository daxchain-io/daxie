package archtest

// determinism_test.go implements the §2.3 AST determinism guard as a REAL failing
// test. It scans the source of internal/service and internal/domain and fails if
// either:
//
//   - imports "os", "net", "crypto/rand", "math/rand", or "math/rand/v2"
//     (non-deterministic I/O / entropy / a globally-seeded RNG); or
//   - contains a call to the wall-clock family: time.Now, time.Since, time.Until,
//     time.After, time.Tick, time.NewTimer, time.NewTicker, time.Sleep — matched
//     through whatever local name "time" is bound to in that file, so an import
//     ALIAS (`import clk "time"`) or a DOT-import (`import . "time"`, where the
//     calls appear bare as `Now()`) cannot smuggle a wall-clock read past the
//     guard.
//
// It PERMITS time.Time / time.Duration *type* references — the core takes time only
// through an injected `clock func() time.Time` (§2.4), and domain.Duration wraps
// time.Duration as a value type. The guard therefore matches CALL expressions whose
// function is a time.<banned> selector, not selector expressions in type position.
//
// Example violations this test CATCHES:
//
//   - `internal/service/convert.go` calling `time.Now()`            → FAIL (wall clock)
//   - `internal/service/service.go` doing `import "os"`             → FAIL (I/O leak)
//   - `internal/domain/error.go` doing `import "crypto/rand"`        → FAIL (entropy)
//
// Only service + domain are guarded; every provider (including abi, which keccak-hashes)
// is exempt by design (§2.3).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// guardedPackages are the relative dirs (under the module root) subject to the guard.
var guardedPackages = []string{
	"internal/service",
	"internal/domain",
}

// bannedImports are import paths that must not appear in a guarded package.
// math/rand and math/rand/v2 are the most likely accidental non-determinism
// source (a global seeded RNG), so they are banned alongside crypto/rand.
var bannedImports = map[string]bool{
	"os":           true,
	"net":          true,
	"crypto/rand":  true,
	"math/rand":    true,
	"math/rand/v2": true,
}

// bannedTimeCalls are the wall-clock / scheduling functions banned as CALL exprs.
var bannedTimeCalls = map[string]bool{
	"Now": true, "Since": true, "Until": true, "After": true,
	"Tick": true, "NewTimer": true, "NewTicker": true, "Sleep": true,
}

func TestDeterminismGuard(t *testing.T) {
	root := moduleRoot(t)

	for _, rel := range guardedPackages {
		dir := filepath.Join(root, rel)
		if _, err := os.Stat(dir); err != nil {
			// The package may not exist yet at this point in the milestone; the guard
			// is still authored and will engage the moment the dir appears. Skip the
			// missing dir rather than fail the build.
			t.Logf("guarded package %s not present yet; skipping (guard remains active once it exists)", rel)
			continue
		}
		scanPackageDir(t, rel, dir)
	}
}

func scanPackageDir(t *testing.T, rel, dir string) {
	t.Helper()
	fset := token.NewFileSet()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	sawGoFile := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// Determinism applies to production code; _test.go fixtures may legitimately
		// use os/time for setup. The guard targets the package's compiled surface.
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		sawGoFile = true
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for _, imp := range bannedImportViolations(f) {
			t.Errorf("DETERMINISM VIOLATION: %s (in %s) imports %q; service/domain must not import os/net/crypto/rand/math-rand (take time via injected clock, I/O via providers, no RNG)", path, rel, imp)
		}
		for _, v := range timeCallViolations(fset, f) {
			t.Errorf("DETERMINISM VIOLATION: %s: %s; the core reads wall-clock only through the injected clock func() time.Time (§2.3/§2.4)", v.pos, v.what)
		}
	}

	if !sawGoFile {
		t.Logf("guarded package %s has no non-test .go files yet; guard idle but active", rel)
	}
}

// bannedImportViolations returns the banned import paths the file imports. It is a
// pure detector (no *testing.T) so the fixture tests can drive it directly.
func bannedImportViolations(f *ast.File) []string {
	var out []string
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if bannedImports[p] {
			out = append(out, p)
		}
	}
	return out
}

// timeLocalNames resolves, per file, the local identifier(s) that the "time"
// package is bound to, so an alias (`import clk "time"`) or dot-import
// (`import . "time"`) cannot smuggle wall-clock calls past the guard. It returns
// the set of selector-qualifier names bound to time (normally just {"time"}, but
// {"clk"} for an alias) and whether time was dot-imported (in which case its
// functions appear as bare identifiers).
func timeLocalNames(f *ast.File) (names map[string]bool, dotImported bool) {
	names = make(map[string]bool)
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil || p != "time" {
			continue
		}
		switch {
		case spec.Name == nil:
			// Plain import: bound to the package name "time".
			names["time"] = true
		case spec.Name.Name == ".":
			dotImported = true
		case spec.Name.Name == "_":
			// Blank import: no usable name; cannot call through it.
		default:
			// Aliased import: bound to the alias identifier.
			names[spec.Name.Name] = true
		}
	}
	return names, dotImported
}

// timeViolation is one detected wall-clock call: its source position and a
// human description (e.g. `calls clk.Now(...)`).
type timeViolation struct {
	pos  token.Position
	what string
}

// timeCallViolations returns every banned wall-clock CALL in the file, resolving
// the per-file local binding of "time" first. It is a pure detector so the
// fixture tests can assert it on synthetic source. A bare `time.Time` in TYPE
// position is a SelectorExpr that is never the Fun of a CallExpr, so it is never
// flagged — exactly the permitted case (§2.3).
func timeCallViolations(fset *token.FileSet, f *ast.File) []timeViolation {
	timeNames, dotImported := timeLocalNames(f)
	var out []timeViolation
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			// Qualified call: <name>.<Sel>(...). Match when <name> is whatever the
			// "time" package is locally bound to in THIS file (package name or alias),
			// not the literal "time".
			ident, ok := fun.X.(*ast.Ident)
			if !ok {
				return true
			}
			if timeNames[ident.Name] && bannedTimeCalls[fun.Sel.Name] {
				out = append(out, timeViolation{
					pos:  fset.Position(call.Pos()),
					what: "calls " + ident.Name + "." + fun.Sel.Name + "(...)",
				})
			}
		case *ast.Ident:
			// Bare call: <Name>(...). Only relevant when time was dot-imported, in
			// which case `Now()` etc. refer to time.Now and must be caught too.
			if dotImported && bannedTimeCalls[fun.Name] {
				out = append(out, timeViolation{
					pos:  fset.Position(call.Pos()),
					what: "calls " + fun.Name + "(...) from a dot-imported \"time\"",
				})
			}
		}
		return true
	})
	return out
}

// parseFixture parses a synthetic Go source string for the guard fixtures.
func parseFixture(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing fixture: %v\n%s", err, src)
	}
	return fset, f
}

// TestGuardCatchesAliasedAndDotTimeImports proves the wall-clock guard is not
// fooled by an import alias or a dot-import of "time" — the escape hatches an
// adversary would reach for. Each fixture MUST produce a violation; the plain
// `time.Time` type reference (a non-call SelectorExpr) MUST NOT.
func TestGuardCatchesAliasedAndDotTimeImports(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantHit bool
	}{
		{
			name:    "plain import time.Now",
			src:     "package x\nimport \"time\"\nvar _ = time.Now()\n",
			wantHit: true,
		},
		{
			name:    "aliased import clk.Now",
			src:     "package x\nimport clk \"time\"\nvar _ = clk.Now()\n",
			wantHit: true,
		},
		{
			name:    "dot import bare Now",
			src:     "package x\nimport . \"time\"\nvar _ = Now()\n",
			wantHit: true,
		},
		{
			name:    "aliased import Since",
			src:     "package x\nimport clk \"time\"\nvar _ = clk.Since(clk.Time{})\n",
			wantHit: true,
		},
		{
			name:    "time.Time TYPE reference is permitted",
			src:     "package x\nimport \"time\"\nvar _ time.Time\nvar _ time.Duration\n",
			wantHit: false,
		},
		{
			name:    "aliased time.Duration TYPE reference is permitted",
			src:     "package x\nimport clk \"time\"\nvar _ clk.Duration\n",
			wantHit: false,
		},
		{
			name: "unrelated package aliased to name time is NOT time-stdlib",
			// An alias `time` pointing at a different package must not false-positive
			// the dot/alias logic — only specs whose path unquotes to "time" count.
			src:     "package x\nimport time \"fmt\"\nvar _ = time.Sprintf(\"\")\n",
			wantHit: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset, f := parseFixture(t, c.src)
			got := timeCallViolations(fset, f)
			if c.wantHit && len(got) == 0 {
				t.Errorf("expected a wall-clock violation, got none for:\n%s", c.src)
			}
			if !c.wantHit && len(got) != 0 {
				t.Errorf("expected NO violation, got %v for:\n%s", got, c.src)
			}
		})
	}
}

// TestGuardBansRandImports proves math/rand and math/rand/v2 (and crypto/rand)
// are banned in guarded packages — the global seeded RNG is the most likely
// accidental non-determinism source.
func TestGuardBansRandImports(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantHit bool
	}{
		{"math/rand", "package x\nimport \"math/rand\"\nvar _ = rand.Int()\n", true},
		{"math/rand/v2", "package x\nimport \"math/rand/v2\"\nvar _ = rand.Int()\n", true},
		{"crypto/rand", "package x\nimport \"crypto/rand\"\nvar _ = rand.Reader\n", true},
		{"os", "package x\nimport \"os\"\nvar _ = os.Args\n", true},
		{"net", "package x\nimport \"net\"\nvar _ net.Addr\n", true},
		// an aliased ban target is still caught (the import PATH, not the name, matches).
		{"aliased math/rand", "package x\nimport mr \"math/rand\"\nvar _ = mr.Int()\n", true},
		// math/big is fine (the deterministic arithmetic the amount math uses).
		{"math/big permitted", "package x\nimport \"math/big\"\nvar _ = new(big.Int)\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, f := parseFixture(t, c.src)
			got := bannedImportViolations(f)
			if c.wantHit && len(got) == 0 {
				t.Errorf("expected a banned-import violation, got none for:\n%s", c.src)
			}
			if !c.wantHit && len(got) != 0 {
				t.Errorf("expected NO violation, got %v for:\n%s", got, c.src)
			}
		})
	}
}
