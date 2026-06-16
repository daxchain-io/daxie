package render

import (
	"bytes"
	"strings"
	"testing"
)

// qr_test.go is the §2.9 "render" seam for the terminal QR: it asserts the
// encoder produces a well-formed symbol (finder patterns, timing lines, quiet
// zone, the expected version for an address-sized payload) and that the render
// layer honors --quiet (the QR is non-essential decoration). It is fully
// self-contained (no keys dependency) so it runs in unit CI from M1.

const sampleAddr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

// A 42-byte payload ("0x" + 40 hex) lands at version 3 (capByteM[2]=42) → a 29×29
// module matrix. This pins the version-selection table.
func TestQRVersionForAddress(t *testing.T) {
	mat, ok := encode([]byte(sampleAddr))
	if !ok {
		t.Fatal("encode returned !ok for a 42-byte address")
	}
	if got := len(mat); got != 29 {
		t.Fatalf("address QR matrix size = %d, want 29 (version 3)", got)
	}
	for _, row := range mat {
		if len(row) != 29 {
			t.Fatalf("non-square matrix row len %d, want 29", len(row))
		}
	}
}

// The three finder patterns are the 7×7 corner markers: dark ring + dark 3×3
// center. Assert all three corners carry the canonical finder.
func TestQRFinderPatterns(t *testing.T) {
	mat, ok := encode([]byte(sampleAddr))
	if !ok {
		t.Fatal("encode !ok")
	}
	n := len(mat)
	corners := [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}}
	for _, c := range corners {
		oy, ox := c[1], c[0]
		// Corners (0,0) and (6,6) of the 7×7 must be dark; (1,1) must be light.
		if !mat[oy][ox] || !mat[oy+6][ox+6] {
			t.Errorf("finder at (%d,%d): outer ring not dark", ox, oy)
		}
		if mat[oy+1][ox+1] {
			t.Errorf("finder at (%d,%d): inner ring (1,1) should be light", ox, oy)
		}
		if !mat[oy+3][ox+3] {
			t.Errorf("finder at (%d,%d): center (3,3) should be dark", ox, oy)
		}
	}
}

// The timing lines on row 6 / column 6 alternate dark/light starting dark.
func TestQRTimingLines(t *testing.T) {
	mat, ok := encode([]byte(sampleAddr))
	if !ok {
		t.Fatal("encode !ok")
	}
	n := len(mat)
	for i := 8; i < n-8; i++ {
		want := i%2 == 0
		if mat[6][i] != want {
			t.Errorf("horizontal timing module (6,%d) = %v, want %v", i, mat[6][i], want)
		}
		if mat[i][6] != want {
			t.Errorf("vertical timing module (%d,6) = %v, want %v", i, mat[i][6], want)
		}
	}
}

// The rendered string has a 4-module (== 2 half-block rows on each vertical edge)
// quiet zone: the first and last rendered rows must be entirely blank.
func TestQRQuietZone(t *testing.T) {
	out, ok := QRString(sampleAddr)
	if !ok {
		t.Fatal("QRString !ok")
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("too few rendered rows: %d", len(lines))
	}
	// Quiet zone is 4 modules == 2 rendered rows (half-block packs 2 modules/row).
	for _, idx := range []int{0, 1, len(lines) - 1, len(lines) - 2} {
		if strings.TrimSpace(lines[idx]) != "" {
			t.Errorf("row %d should be blank (quiet zone), got %q", idx, lines[idx])
		}
	}
}

// Render honors --quiet: the QR block is suppressed (it is decoration, not the
// essential address line, §5.9).
func TestQRQuietModeSuppresses(t *testing.T) {
	var buf bytes.Buffer
	QR(&buf, Mode{Quiet: true}, sampleAddr)
	if buf.Len() != 0 {
		t.Errorf("--quiet should suppress the QR block, got %d bytes", buf.Len())
	}

	buf.Reset()
	QR(&buf, Mode{}, sampleAddr)
	if buf.Len() == 0 {
		t.Error("non-quiet QR produced no output")
	}
	if !strings.ContainsAny(buf.String(), "█▀▄") {
		t.Error("QR output contains no block glyphs")
	}
}

// Determinism: the same input renders byte-identically across calls (mask
// selection is deterministic), so golden comparisons downstream are stable.
func TestQRDeterministic(t *testing.T) {
	a, _ := QRString(sampleAddr)
	b, _ := QRString(sampleAddr)
	if a != b {
		t.Error("QRString is not deterministic for the same input")
	}
}

// A short payload still encodes (version 1); an over-long one (> v10 byte cap at
// M, 213 bytes) returns !ok so the caller falls back to the address line.
func TestQRBoundaries(t *testing.T) {
	if _, ok := QRString("0x01"); !ok {
		t.Error("short payload should encode")
	}
	long := strings.Repeat("a", 300)
	if _, ok := QRString(long); ok {
		t.Error("over-capacity payload should return !ok")
	}
}
