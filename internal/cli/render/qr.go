// qr.go is a self-contained, pure-Go QR-code encoder for rendering an Ethereum
// address as a terminal QR (cli-spec §account `--qr`; design §1 output table
// "terminal QR"). It deliberately depends on NOTHING beyond the standard library:
// the alternative (github.com/skip2/go-qrcode) is a fine library, but adding a
// module for ~one call site is the "heavy dep if avoidable" the M1 brief asks us
// to avoid, and a QR encoder is a closed, well-specified algorithm. This
// implementation covers byte mode, versions 1–10, and the four EC levels with
// full mask selection — comfortably more than the 42-byte "0x…" address payload
// needs (it lands at version 3–4 / level M).
//
// Rendering uses Unicode half-blocks (one cell == two vertical modules) so the QR
// is roughly square in a normal terminal; a 4-module quiet zone frames it per the
// spec so phone scanners lock on. The address line is the ESSENTIAL output and is
// printed by the caller; the QR block is decoration suppressed under --quiet.
package render

import (
	"io"
	"strings"
)

// ── public surface ───────────────────────────────────────────────────────────

// QRString encodes s and returns the terminal QR as a multi-line string (each
// line ends in '\n'). It returns ("", false) if s does not fit the supported
// version range (never expected for a 42-char address). Callers gate on the bool
// and fall back to printing the address alone.
func QRString(s string) (string, bool) {
	m, ok := encode([]byte(s))
	if !ok {
		return "", false
	}
	return renderHalfBlocks(m), true
}

// QR writes the terminal QR for s to w, honoring Quiet (the QR is non-essential
// decoration). It is a no-op (no error) when Quiet is set or when s does not fit.
// The address itself is printed by the caller, not here, so a suppressed/failed
// QR never hides the essential output.
func QR(w io.Writer, m Mode, s string) {
	if m.Quiet {
		return
	}
	out, ok := QRString(s)
	if !ok {
		return
	}
	_, _ = io.WriteString(w, out)
}

// ── module matrix rendering ──────────────────────────────────────────────────

// renderHalfBlocks turns the boolean module matrix into terminal text. Two
// vertical modules share one character cell via the half-block glyphs; a 4-module
// quiet zone is added around the symbol. Dark modules render as the cell's "ink".
func renderHalfBlocks(mat [][]bool) string {
	const quiet = 4
	n := len(mat)
	size := n + quiet*2

	// padded[y][x] true == dark module (default light in the quiet zone).
	padded := make([][]bool, size)
	for y := range padded {
		padded[y] = make([]bool, size)
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			padded[y+quiet][x+quiet] = mat[y][x]
		}
	}

	var b strings.Builder
	// Walk two rows at a time: top module -> upper half, bottom module -> lower.
	for y := 0; y < size; y += 2 {
		for x := 0; x < size; x++ {
			top := padded[y][x]
			bot := false
			if y+1 < size {
				bot = padded[y+1][x]
			}
			b.WriteString(cellGlyph(top, bot))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// cellGlyph maps (topDark, bottomDark) to a half-block. Dark == "ink"; light ==
// the terminal background. Using the block glyphs (not ANSI color) keeps the
// output copy-pasteable and color-scheme independent.
func cellGlyph(top, bottom bool) string {
	switch {
	case top && bottom:
		return "█" // full block
	case top && !bottom:
		return "▀" // upper half
	case !top && bottom:
		return "▄" // lower half
	default:
		return " "
	}
}

// ── encoder ──────────────────────────────────────────────────────────────────
//
// The encoder implements the QR spec for byte mode: data + EC codeword
// generation (Reed-Solomon over GF(256)), matrix placement (finders, timing,
// alignment, format/version info), the eight data masks, and penalty-based mask
// selection. Constants below are the spec tables for versions 1–10. The error
// correction level is fixed at M (~15%) — the address default, a good balance of
// robustness and density for a phone scan; every capacity/EC/format table below
// is therefore the level-M row only.

// capByteM is the byte-mode data capacity (in bytes) at EC level M for versions
// 1..10 (index 0 == version 1). From the QR spec capacity tables.
var capByteM = []int{14, 26, 42, 62, 84, 106, 122, 152, 180, 213}

// dataCodewordsM is data codewords (capacity in codewords) per version 1..10 at M.
var dataCodewordsM = []int{16, 28, 44, 64, 86, 108, 124, 154, 182, 216}

// ecPerBlockM is EC codewords per block per version 1..10 at level M.
var ecPerBlockM = []int{10, 16, 26, 18, 24, 16, 18, 22, 22, 26}

// blocksM is the (group1Blocks, group1DataCW, group2Blocks, group2DataCW) block
// layout per version 1..10 at level M. group2 may be zero.
type blockLayout struct{ g1, g1cw, g2, g2cw int }

var blocksM = []blockLayout{
	{1, 16, 0, 0},  // v1
	{1, 28, 0, 0},  // v2
	{1, 44, 0, 0},  // v3
	{2, 32, 0, 0},  // v4
	{2, 43, 0, 0},  // v5
	{4, 27, 0, 0},  // v6
	{4, 31, 0, 0},  // v7
	{2, 38, 2, 39}, // v8
	{3, 36, 2, 37}, // v9
	{4, 43, 1, 44}, // v10
}

// alignmentCenters is the alignment-pattern center coordinate list per version
// 1..10 (version 1 has none). The matrix code crosses them to place 5×5 patterns.
var alignmentCenters = [][]int{
	{},          // v1
	{6, 18},     // v2
	{6, 22},     // v3
	{6, 26},     // v4
	{6, 30},     // v5
	{6, 34},     // v6
	{6, 22, 38}, // v7
	{6, 24, 42}, // v8
	{6, 26, 46}, // v9
	{6, 28, 50}, // v10
}

// encode builds the smallest-version byte-mode QR for data at chosenEC and runs
// mask selection, returning the dark/light module matrix.
func encode(data []byte) ([][]bool, bool) {
	ver := pickVersion(len(data))
	if ver == 0 {
		return nil, false
	}
	vi := ver - 1

	bits := buildDataBits(data, ver)
	dataCW := bitsToCodewords(bits, dataCodewordsM[vi])
	final := interleave(dataCW, vi)

	best := placeAndMask(final, ver)
	return best, true
}

// pickVersion returns the smallest version (1..10) whose level-M byte capacity
// holds n bytes, or 0 if none does.
func pickVersion(n int) int {
	for v := 1; v <= len(capByteM); v++ {
		if n <= capByteM[v-1] {
			return v
		}
	}
	return 0
}

// buildDataBits assembles the byte-mode bitstream: mode indicator (0100), the
// character count, the data bytes, the 0000 terminator, byte padding, and the
// alternating pad bytes (0xEC, 0x11) to fill the data capacity.
func buildDataBits(data []byte, ver int) []bool {
	var bits []bool
	// Mode indicator: byte mode = 0100.
	bits = appendBits(bits, 0b0100, 4)
	// Character count indicator: 8 bits for versions 1–9, 16 bits for 10–26.
	ccLen := 8
	if ver >= 10 {
		ccLen = 16
	}
	bits = appendBits(bits, uint(len(data)), ccLen)
	for _, b := range data {
		bits = appendBits(bits, uint(b), 8)
	}

	capBits := dataCodewordsM[ver-1] * 8
	// Terminator: up to four 0 bits.
	term := capBits - len(bits)
	if term > 4 {
		term = 4
	}
	if term > 0 {
		bits = appendBits(bits, 0, term)
	}
	// Pad to a byte boundary.
	if rem := len(bits) % 8; rem != 0 {
		bits = appendBits(bits, 0, 8-rem)
	}
	// Pad bytes alternate 0xEC, 0x11.
	pad := []uint{0xEC, 0x11}
	for i := 0; len(bits) < capBits; i++ {
		bits = appendBits(bits, pad[i%2], 8)
	}
	return bits
}

// bitsToCodewords packs the bitstream into n data codewords (bytes).
func bitsToCodewords(bits []bool, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			idx := i*8 + j
			if idx < len(bits) && bits[idx] {
				b |= 1 << (7 - j)
			}
		}
		out[i] = b
	}
	return out
}

// interleave splits data codewords into blocks, computes each block's EC
// codewords, and interleaves data-then-EC per the spec to produce the final
// codeword sequence.
func interleave(dataCW []byte, vi int) []byte {
	lay := blocksM[vi]
	ecLen := ecPerBlockM[vi]

	type block struct{ data, ec []byte }
	var blocks []block

	pos := 0
	addBlocks := func(count, cw int) {
		for i := 0; i < count; i++ {
			d := dataCW[pos : pos+cw]
			pos += cw
			blocks = append(blocks, block{data: d, ec: reedSolomon(d, ecLen)})
		}
	}
	addBlocks(lay.g1, lay.g1cw)
	if lay.g2 > 0 {
		addBlocks(lay.g2, lay.g2cw)
	}

	var out []byte
	// Interleave data codewords across blocks, column by column.
	maxData := lay.g1cw
	if lay.g2cw > maxData {
		maxData = lay.g2cw
	}
	for c := 0; c < maxData; c++ {
		for _, bl := range blocks {
			if c < len(bl.data) {
				out = append(out, bl.data[c])
			}
		}
	}
	// Interleave EC codewords (all blocks share ecLen).
	for c := 0; c < ecLen; c++ {
		for _, bl := range blocks {
			out = append(out, bl.ec[c])
		}
	}
	return out
}

// ── Reed-Solomon over GF(256) (QR's primitive polynomial 0x11D) ──────────────

var gfExp [512]byte
var gfLog [256]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsGenerator returns the generator polynomial of degree n.
func rsGenerator(n int) []byte {
	g := []byte{1}
	for i := 0; i < n; i++ {
		// multiply g by (x - α^i)
		next := make([]byte, len(g)+1)
		for j := 0; j < len(g); j++ {
			next[j] ^= gfMul(g[j], gfExp[i])
			next[j+1] ^= g[j]
		}
		g = next
	}
	return g
}

// reedSolomon returns the n EC codewords for the data block.
func reedSolomon(data []byte, n int) []byte {
	gen := rsGenerator(n)
	rem := make([]byte, len(data)+n)
	copy(rem, data)
	for i := 0; i < len(data); i++ {
		coef := rem[i]
		if coef == 0 {
			continue
		}
		for j := 0; j < len(gen); j++ {
			rem[i+j] ^= gfMul(gen[j], coef)
		}
	}
	return rem[len(data):]
}

// ── matrix placement + masking ───────────────────────────────────────────────

// matrix carries the module values plus a parallel "function module" mask: fn[y][x]
// marks a reserved module (finder/timing/alignment/format/version) that data
// placement and data-masking must skip.
type matrix struct {
	size int
	val  [][]bool
	fn   [][]bool
}

func newMatrix(size int) *matrix {
	m := &matrix{size: size, val: make([][]bool, size), fn: make([][]bool, size)}
	for i := 0; i < size; i++ {
		m.val[i] = make([]bool, size)
		m.fn[i] = make([]bool, size)
	}
	return m
}

func (m *matrix) set(x, y int, dark, fnmod bool) {
	m.val[y][x] = dark
	if fnmod {
		m.fn[y][x] = true
	}
}

// placeAndMask builds the function patterns, places data with each of the eight
// masks, scores penalties, and returns the lowest-penalty matrix's modules.
func placeAndMask(final []byte, ver int) [][]bool {
	size := ver*4 + 17

	base := newMatrix(size)
	placeFinders(base)
	placeTiming(base)
	placeAlignment(base, ver)
	// Dark module.
	base.set(8, size-8, true, true)
	reserveFormat(base)
	if ver >= 7 {
		reserveVersion(base)
	}

	var bestMatrix [][]bool
	bestPenalty := 1 << 30

	for mask := 0; mask < 8; mask++ {
		m := cloneMatrix(base)
		placeData(m, final, mask)
		writeFormat(m, mask)
		if ver >= 7 {
			writeVersion(m, ver)
		}
		p := penalty(m)
		if p < bestPenalty {
			bestPenalty = p
			bestMatrix = copyVals(m)
		}
	}
	return bestMatrix
}

func cloneMatrix(src *matrix) *matrix {
	m := newMatrix(src.size)
	for y := 0; y < src.size; y++ {
		copy(m.val[y], src.val[y])
		copy(m.fn[y], src.fn[y])
	}
	return m
}

func copyVals(m *matrix) [][]bool {
	out := make([][]bool, m.size)
	for y := 0; y < m.size; y++ {
		out[y] = make([]bool, m.size)
		copy(out[y], m.val[y])
	}
	return out
}

// placeFinders draws the three 7×7 finder patterns and their separators.
func placeFinders(m *matrix) {
	corners := [][2]int{{0, 0}, {m.size - 7, 0}, {0, m.size - 7}}
	for _, c := range corners {
		ox, oy := c[0], c[1]
		for dy := -1; dy <= 7; dy++ {
			for dx := -1; dx <= 7; dx++ {
				x, y := ox+dx, oy+dy
				if x < 0 || y < 0 || x >= m.size || y >= m.size {
					continue
				}
				dark := false
				if dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6 {
					// 7×7 pattern: border ring + 3×3 center.
					if dx == 0 || dx == 6 || dy == 0 || dy == 6 ||
						(dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4) {
						dark = true
					}
				}
				m.set(x, y, dark, true)
			}
		}
	}
}

// placeTiming draws the two timing lines.
func placeTiming(m *matrix) {
	for i := 8; i < m.size-8; i++ {
		dark := i%2 == 0
		m.set(i, 6, dark, true)
		m.set(6, i, dark, true)
	}
}

// placeAlignment draws every 5×5 alignment pattern that does not overlap a finder.
func placeAlignment(m *matrix, ver int) {
	centers := alignmentCenters[ver-1]
	for _, cy := range centers {
		for _, cx := range centers {
			// Skip the three that collide with finder patterns.
			if (cx == 6 && cy == 6) ||
				(cx == 6 && cy == m.size-7) ||
				(cx == m.size-7 && cy == 6) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					dark := dx == -2 || dx == 2 || dy == -2 || dy == 2 || (dx == 0 && dy == 0)
					m.set(cx+dx, cy+dy, dark, true)
				}
			}
		}
	}
}

// reserveFormat marks the format-info modules as function cells (values written
// later per mask).
func reserveFormat(m *matrix) {
	for i := 0; i <= 8; i++ {
		if i != 6 {
			m.fn[8][i] = true
			m.fn[i][8] = true
		}
	}
	for i := 0; i < 8; i++ {
		m.fn[8][m.size-1-i] = true
		m.fn[m.size-1-i][8] = true
	}
	m.fn[8][8] = true
}

// reserveVersion marks the version-info blocks (versions ≥ 7) as function cells.
func reserveVersion(m *matrix) {
	for i := 0; i < 6; i++ {
		for j := 0; j < 3; j++ {
			m.fn[m.size-11+j][i] = true
			m.fn[i][m.size-11+j] = true
		}
	}
}

// placeData lays the final codeword bitstream into the non-function modules in
// the spec's zig-zag order, applying the data mask as it goes.
func placeData(m *matrix, data []byte, mask int) {
	bitAt := func(i int) bool {
		if i/8 >= len(data) {
			return false
		}
		return data[i/8]&(1<<(7-uint(i%8))) != 0
	}
	bit := 0
	up := true
	for col := m.size - 1; col > 0; col -= 2 {
		if col == 6 { // skip the vertical timing column
			col--
		}
		for n := 0; n < m.size; n++ {
			y := n
			if up {
				y = m.size - 1 - n
			}
			for c := 0; c < 2; c++ {
				x := col - c
				if m.fn[y][x] {
					continue
				}
				v := bitAt(bit)
				if maskFn(mask, x, y) {
					v = !v
				}
				m.val[y][x] = v
				bit++
			}
		}
		up = !up
	}
}

// maskFn returns whether module (x,y) is flipped by data mask `mask`.
func maskFn(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return (x*y)%2+(x*y)%3 == 0
	case 6:
		return ((x*y)%2+(x*y)%3)%2 == 0
	case 7:
		return ((x+y)%2+(x*y)%3)%2 == 0
	}
	return false
}

// ── format & version information ─────────────────────────────────────────────

// formatStringsM are the 15-bit format-information strings for EC level M, masks
// 0..7, precomputed per the QR standard (Annex C: 5 data bits BCH(15,5)-encoded
// with generator 0x537, then XOR'd with the 0x5412 spec mask). Using the
// published constants avoids a hand-rolled BCH that is easy to get subtly wrong;
// chosenEC is fixed at M so this single row suffices. Bit i of the value is
// placed at format position i below (the spec's bit 14 == MSB).
var formatStringsM = [8]uint{
	0x5412, 0x5125, 0x5E7C, 0x5B4B,
	0x45F9, 0x40CE, 0x4F97, 0x4AA0,
}

// writeFormat writes the 15-bit format string for (chosenEC=M, mask) into both
// copies. The bit ordering follows the spec: the format value's bit 14 is the
// most significant; get(i) returns format bit i.
func writeFormat(m *matrix, mask int) {
	format := formatStringsM[mask]
	// get(i) is format bit i, where i runs 0 (LSB) .. 14 (MSB).
	get := func(i int) bool { return format&(1<<uint(i)) != 0 }

	// Copy 1: the L-shape around the top-left finder. Spec placement maps format
	// bit (14-k) to the k-th module along the standard order.
	// Top-left horizontal (row 8): columns 0..5, then 7,8; vertical (col 8): rows
	// 8,7, then 5..0.
	m.val[8][0] = get(14)
	m.val[8][1] = get(13)
	m.val[8][2] = get(12)
	m.val[8][3] = get(11)
	m.val[8][4] = get(10)
	m.val[8][5] = get(9)
	m.val[8][7] = get(8)
	m.val[8][8] = get(7)
	m.val[7][8] = get(6)
	m.val[5][8] = get(5)
	m.val[4][8] = get(4)
	m.val[3][8] = get(3)
	m.val[2][8] = get(2)
	m.val[1][8] = get(1)
	m.val[0][8] = get(0)

	// Copy 2: split between the bottom-left (vertical, col 8) and top-right
	// (horizontal, row 8). Bottom-left rows size-1 .. size-7 carry bits 14..8;
	// top-right cols size-8 .. size-1 carry bits 7..0.
	m.val[m.size-1][8] = get(14)
	m.val[m.size-2][8] = get(13)
	m.val[m.size-3][8] = get(12)
	m.val[m.size-4][8] = get(11)
	m.val[m.size-5][8] = get(10)
	m.val[m.size-6][8] = get(9)
	m.val[m.size-7][8] = get(8)
	m.val[8][m.size-8] = get(7)
	m.val[8][m.size-7] = get(6)
	m.val[8][m.size-6] = get(5)
	m.val[8][m.size-5] = get(4)
	m.val[8][m.size-4] = get(3)
	m.val[8][m.size-3] = get(2)
	m.val[8][m.size-2] = get(1)
	m.val[8][m.size-1] = get(0)
}

// versionInfo holds the precomputed 18-bit version strings (versions 7–10; lower
// versions carry none). Index is version-7.
var versionInfo = map[int]uint{
	7:  0x07C94,
	8:  0x085BC,
	9:  0x09A99,
	10: 0x0A4D3,
}

// writeVersion writes the 18-bit version info for versions ≥ 7.
func writeVersion(m *matrix, ver int) {
	v, ok := versionInfo[ver]
	if !ok {
		return
	}
	for i := 0; i < 18; i++ {
		bit := v&(1<<uint(i)) != 0
		row := i / 3
		col := i % 3
		m.val[m.size-11+col][row] = bit
		m.val[row][m.size-11+col] = bit
	}
}

// ── penalty scoring (mask selection) ─────────────────────────────────────────

func penalty(m *matrix) int {
	return rule1(m) + rule2(m) + rule3(m) + rule4(m)
}

// rule1: runs of ≥5 same-color modules in a row/column.
func rule1(m *matrix) int {
	score := 0
	count := func(get func(i, j int) bool) int {
		s := 0
		for a := 0; a < m.size; a++ {
			run := 1
			for b := 1; b < m.size; b++ {
				if get(a, b) == get(a, b-1) {
					run++
				} else {
					if run >= 5 {
						s += 3 + (run - 5)
					}
					run = 1
				}
			}
			if run >= 5 {
				s += 3 + (run - 5)
			}
		}
		return s
	}
	score += count(func(a, b int) bool { return m.val[a][b] }) // rows
	score += count(func(a, b int) bool { return m.val[b][a] }) // cols
	return score
}

// rule2: 2×2 same-color blocks.
func rule2(m *matrix) int {
	score := 0
	for y := 0; y < m.size-1; y++ {
		for x := 0; x < m.size-1; x++ {
			v := m.val[y][x]
			if m.val[y][x+1] == v && m.val[y+1][x] == v && m.val[y+1][x+1] == v {
				score += 3
			}
		}
	}
	return score
}

// rule3: finder-like 1:1:3:1:1 patterns in rows/columns.
func rule3(m *matrix) int {
	pat1 := []bool{true, false, true, true, true, false, true, false, false, false, false}
	pat2 := []bool{false, false, false, false, true, false, true, true, true, false, true}
	score := 0
	matches := func(get func(i int) bool, off int, pat []bool) bool {
		for k := 0; k < 11; k++ {
			if get(off+k) != pat[k] {
				return false
			}
		}
		return true
	}
	match := func(get func(i int) bool, off int) bool {
		return matches(get, off, pat1) || matches(get, off, pat2)
	}
	for y := 0; y < m.size; y++ {
		for x := 0; x <= m.size-11; x++ {
			if match(func(i int) bool { return m.val[y][i] }, x) {
				score += 40
			}
		}
	}
	for x := 0; x < m.size; x++ {
		for y := 0; y <= m.size-11; y++ {
			if match(func(i int) bool { return m.val[i][x] }, y) {
				score += 40
			}
		}
	}
	return score
}

// rule4: proportion of dark modules deviating from 50%.
func rule4(m *matrix) int {
	dark := 0
	total := m.size * m.size
	for y := 0; y < m.size; y++ {
		for x := 0; x < m.size; x++ {
			if m.val[y][x] {
				dark++
			}
		}
	}
	percent := dark * 100 / total
	prev := percent / 5 * 5
	next := prev + 5
	a := abs(prev-50) / 5
	b := abs(next-50) / 5
	if a < b {
		return a * 10
	}
	return b * 10
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// ── bit helpers ──────────────────────────────────────────────────────────────

func appendBits(bits []bool, v uint, n int) []bool {
	for i := n - 1; i >= 0; i-- {
		bits = append(bits, v&(1<<uint(i)) != 0)
	}
	return bits
}
