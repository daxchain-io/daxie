package journal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/daxchain-io/daxie/internal/fsx"
)

// compactSupersededThreshold / compactSizeThreshold are the §5.6 compaction
// triggers: rewrite the latest-snapshot-per-id when superseded (folded-away) lines
// exceed 5000 OR the file exceeds 8 MiB. Compaction runs under the SAME journal
// flock as the append that triggered it (the caller already holds it).
const (
	compactSupersededThreshold = 5000
	compactSizeThreshold       = 8 << 20 // 8 MiB
)

// readAll reads every record from the chain's journal file in seq-append order,
// tolerating torn/corrupt lines (§5.6): a mid-file non-parsing line is SKIPPED with
// a stderr warning (never fatal); a non-parsing FINAL line (a partial write
// interrupted by a crash) is truncated to the last newline and dropped. It returns
// the parsed records and the current max seq (0 for an empty/missing file).
//
// A missing file (fresh install) is NOT an error — it folds to empty (§7.3). The
// caller holds the journal flock (exclusive for append, shared for read). repair is
// true ONLY under the exclusive lock (Append/SetState): a torn final line is then
// truncated in place. Under the shared read lock repair is false — the partial line
// is dropped in memory but the file is left for a writer to repair, since rewriting
// under a shared lock could race a concurrent append.
func (s *Store) readAll(chainID uint64, repair bool) (recs []*Record, maxSeq uint64, err error) {
	path := s.filePath(chainID)
	data, rerr := os.ReadFile(path) // #nosec G304 -- path is the per-chain journal file under the state dir
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, errWrap(CodeStateCorrupt, "cannot read journal file", rerr)
	}

	// Determine whether the final line is complete (ends in '\n'). A partial final
	// line (crash mid-write) is dropped AND truncated from the file so the next
	// append starts clean — but truncation only happens when we hold the EXCLUSIVE
	// lock (append path). On the read path we just drop it in memory.
	lines := splitLines(data)
	hasTrailingNL := endsWithNewline(data)
	for i, line := range lines {
		isFinal := i == len(lines)-1
		// A non-newline-terminated FINAL segment is torn by definition (§5.6: a
		// record is one line = one write(2), terminated by '\n'). A partial write
		// interrupted by a crash leaves the tail un-terminated even if the JSON
		// happens to be complete; drop it and repair the file to the last newline.
		if isFinal && !hasTrailingNL && len(bytes.TrimSpace(line)) > 0 {
			_, _ = fmt.Fprintf(s.warnWriter(), "daxie: journal: dropping torn final line in %s (partial write recovered)\n", path)
			if repair {
				if terr := s.truncateTornFinal(path, data); terr != nil {
					return nil, 0, terr
				}
			}
			continue
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		var r Record
		if jerr := json.Unmarshal(trimmed, &r); jerr != nil {
			// A corrupt line (newline-terminated but unparseable): skip with a
			// warning. last-wins-per-id means this costs at most one transition;
			// reconciliation re-derives the rest from the chain.
			_, _ = fmt.Fprintf(s.warnWriter(), "daxie: journal: skipping corrupt line %d in %s\n", i+1, path)
			continue
		}
		rc := r // copy so &rc is stable per iteration
		recs = append(recs, &rc)
		if rc.Seq > maxSeq {
			maxSeq = rc.Seq
		}
	}
	return recs, maxSeq, nil
}

// truncateTornFinal rewrites path with everything up to and including the last
// newline, dropping a trailing partial record. It is only safe under the exclusive
// flock; on the read (shared-lock) path the partial line is already dropped in
// memory and this is a no-op repair we skip by only calling it from readAll when the
// data has no trailing newline. It uses fsx.WriteAtomic so the repair is itself
// crash-safe (the same temp+rename+fsync discipline as compaction).
func (s *Store) truncateTornFinal(path string, data []byte) error {
	idx := bytes.LastIndexByte(data, '\n')
	var repaired []byte
	if idx >= 0 {
		repaired = data[:idx+1]
	}
	// repaired may be empty (the file was a single partial line) — that is a valid
	// empty journal. WriteAtomic of zero bytes is fine.
	if werr := fsx.WriteAtomic(path, repaired, 0o600); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errWrap(CodeStateCorrupt, "journal is read-only; cannot repair torn final line", werr)
		}
		return errWrap(CodeStateCorrupt, "cannot repair torn final line", werr)
	}
	return nil
}

// appendLine serializes rec to one line and appends it to the chain's journal file
// with the §5.6 discipline: open the file FRESH by path (O_APPEND|O_CREATE — never a
// long-lived fd, so an append after another process's compact-rename lands in the
// live file, not the unlinked old inode), write exactly one line = one write(2),
// fsync, close. The caller holds the exclusive journal flock.
func (s *Store) appendLine(chainID uint64, rec *Record) error {
	b, merr := json.Marshal(rec)
	if merr != nil {
		return errWrap(CodeStateCorrupt, "cannot encode journal record", merr)
	}
	b = append(b, '\n')

	path := s.filePath(chainID)
	f, oerr := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- per-chain journal file under the state dir
	if oerr != nil {
		if fsx.IsReadOnly(oerr) {
			return errWrap(CodeStateCorrupt, "journal is read-only; cannot append", oerr)
		}
		return errWrap(CodeStateCorrupt, "cannot open journal for append", oerr)
	}
	// One write(2): a single Write call so a crash leaves either the full line or a
	// torn tail (recovered by truncateTornFinal), never an interleaved record.
	if _, werr := f.Write(b); werr != nil {
		_ = f.Close()
		return errWrap(CodeStateCorrupt, "cannot append journal record", werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return errWrap(CodeStateCorrupt, "cannot fsync journal record", serr)
	}
	if cerr := f.Close(); cerr != nil {
		return errWrap(CodeStateCorrupt, "cannot close journal file", cerr)
	}
	return nil
}

// maybeCompact rewrites the journal to one latest-snapshot line per id when the
// superseded-line or size threshold is crossed (§5.6). Terminal records are KEPT
// (the journal IS `tx list` history); only superseded (folded-away) intermediate
// lines are dropped. It runs under the exclusive flock the caller already holds, via
// fsx.WriteAtomic (temp+fsync+rename), and because appends always open fresh by
// path, an in-flight append from another process after the rename lands correctly.
//
// preRecs is the slice as read BEFORE the triggering append; latest is the record
// just appended (so the snapshot reflects it without a re-read).
func (s *Store) maybeCompact(chainID uint64, preRecs []*Record, latest *Record) error {
	// Reconstruct the full post-append record set (preRecs + the new line) and fold.
	all := make([]*Record, 0, len(preRecs)+1)
	all = append(all, preRecs...)
	all = append(all, latest)

	folded := foldLatest(all)
	totalLines := len(all)
	supersededLines := totalLines - len(folded)

	if supersededLines < compactSupersededThreshold {
		// Also check the on-disk size; cheap stat, only when the line count didn't
		// already trip the trigger.
		path := s.filePath(chainID)
		if fi, err := os.Stat(path); err == nil && fi.Size() < compactSizeThreshold {
			return nil
		} else if err != nil {
			// Stat failure is non-fatal for the append we just durably wrote; skip
			// compaction this round.
			return nil //nolint:nilerr // the append already succeeded; a failed stat just defers compaction
		}
	}

	return s.compact(chainID, folded)
}

// compact writes the folded snapshot (latest line per id, seq-ordered ascending) to
// the journal file via WriteAtomic. Seq values are PRESERVED (not renumbered) so
// foldLatest's "higher seq wins" invariant and any in-memory reference to a seq stay
// valid; the next append reads the preserved max seq and continues. The caller holds
// the exclusive flock.
func (s *Store) compact(chainID uint64, folded map[string]*Record) error {
	snap := make([]*Record, 0, len(folded))
	for _, r := range folded {
		snap = append(snap, r)
	}
	// Ascending seq so the file reads in historical order and the final line is the
	// highest seq (matching the append-only invariant for readAll's maxSeq).
	for i := 0; i < len(snap); i++ {
		for j := i + 1; j < len(snap); j++ {
			if snap[j].Seq < snap[i].Seq {
				snap[i], snap[j] = snap[j], snap[i]
			}
		}
	}

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	enc := json.NewEncoder(w)
	for _, r := range snap {
		if err := enc.Encode(r); err != nil { // Encode appends '\n'
			return errWrap(CodeStateCorrupt, "cannot encode journal snapshot", err)
		}
	}
	if err := w.Flush(); err != nil {
		return errWrap(CodeStateCorrupt, "cannot buffer journal snapshot", err)
	}
	if werr := fsx.WriteAtomic(s.filePath(chainID), buf.Bytes(), 0o600); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errWrap(CodeStateCorrupt, "journal is read-only; cannot compact", werr)
		}
		return errWrap(CodeStateCorrupt, "cannot compact journal", werr)
	}
	return nil
}

// splitLines splits data on '\n', keeping the (possibly partial) final segment. A
// trailing newline yields a final empty segment which readAll skips; the absence of
// one signals a torn final line.
func splitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	return bytes.Split(data, []byte{'\n'})
}

// endsWithNewline reports whether data's last byte is '\n' (a complete final line).
func endsWithNewline(data []byte) bool {
	return len(data) > 0 && data[len(data)-1] == '\n'
}
