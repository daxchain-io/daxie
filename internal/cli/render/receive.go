package render

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/daxchain-io/daxie/internal/domain"
)

// receive.go builds the EventSink for `daxie receive` (§5.8/§5.9). It is the ONE
// command whose progress stream is the PRIMARY output on STDOUT — the single
// sanctioned exception to the single-object-on-stdout rule. The binding contract:
//
//   - `send`/`wait` route progress to STDERR (render.StderrProgress); `receive`
//     routes its NDJSON to STDOUT. The address is emitted UP FRONT (the first
//     `listening` line) so a human can share it / an agent can hand it to the
//     counterparty BEFORE the command blocks.
//   - Under --json the stream is line-delimited NDJSON on stdout: every line
//     carries `"v":1`, all amounts are base-unit decimal STRINGS (no float, §2.5),
//     and the TERMINAL line is `complete` (exit 0) or `timeout` (exit 8). The
//     per-transfer `confirmed` line is NEVER terminal.
//   - Under human mode the same events render as short readable lines on STDOUT.
//
// Why a renderer owns the exact line shape (not `encoding/json` over the whole
// domain.Event): the §5.8 examples use `"confirmations"` (a number) on the
// listening.target object AND on the confirming line, and `"target"` (a number)
// on confirming — keys the send/wait path already binds on the flat Event. To
// emit the §5.8 lines VERBATIM with no stray send/wait keys and no key collision,
// each receive kind is marshaled through a small purpose-built struct here. The
// domain.Event CARRIES the data (the M8 receive fields); this renderer maps it to
// the exact wire shape per kind.

// ReceiveStream returns the EventSink the receive command hands to svc.Receive.
// stdout is the receive stream destination (NOT stderr). jsonMode selects NDJSON
// (one JSON object per line) vs the human-readable lines. A nil writer yields a
// no-op sink (the core's Emit contract tolerates nil).
//
// The sink only ever owns STDOUT — the receive single-object exception lives
// here, by construction, so a future event with a missing Stream hint can never
// leak the receive stream onto stderr.
func ReceiveStream(stdout io.Writer, jsonMode bool) domain.EventSink {
	if stdout == nil {
		return nil
	}
	if jsonMode {
		return func(ev domain.Event) {
			line, ok := receiveJSONLine(ev)
			if !ok {
				return
			}
			_, _ = stdout.Write(line)
			_, _ = io.WriteString(stdout, "\n")
		}
	}
	return func(ev domain.Event) {
		line := receiveHumanLine(ev)
		if line == "" {
			return
		}
		_, _ = io.WriteString(stdout, line+"\n")
	}
}

// ── NDJSON wire structs (one per kind, byte-exact to §5.8) ────────────────────
//
// Field ORDER follows the struct field order under encoding/json; the §5.8
// examples are wrapped for readability but are single JSON objects, so the only
// hard contract is the KEY SET + `"v":1` + decimal-string amounts, which these
// structs satisfy. Pointer/omitempty choices mirror the examples: `token_id` is
// rendered as JSON `null` on a non-NFT detection (a *string left nil with NO
// omitempty), `log_index` is omitted when absent (balance-delta), etc.

type wireListening struct {
	V       int            `json:"v"`
	Event   string         `json:"event"`
	Address string         `json:"address"`
	Network string         `json:"network,omitempty"`
	ChainID uint64         `json:"chain_id,omitempty"`
	Asset   *wireAsset     `json:"asset,omitempty"`
	Target  wireTargetSpec `json:"target"`
	FromBlk uint64         `json:"from_block"`
	TS      string         `json:"ts,omitempty"`
}

type wireAsset struct {
	Kind     string `json:"kind"`
	Contract string `json:"contract,omitempty"`
	Alias    string `json:"alias,omitempty"`
	Decimals int    `json:"decimals,omitempty"`
	TokenID  string `json:"token_id,omitempty"`
}

type wireTargetSpec struct {
	Mode          string  `json:"mode"`
	Amount        string  `json:"amount,omitempty"`
	Confirmations uint64  `json:"confirmations"`
	Timeout       *string `json:"timeout"` // null ⇒ unbounded (matches §5.8 "timeout":null)
}

type wireDetected struct {
	V                  int     `json:"v"`
	Event              string  `json:"event"`
	TxHash             *string `json:"tx_hash"` // null for balance-delta (no bound tx)
	LogIndex           *int    `json:"log_index,omitempty"`
	From               string  `json:"from,omitempty"`
	Value              string  `json:"value"`
	TokenID            *string `json:"token_id"` // null when not an NFT (§5.8 erc20/eth examples)
	Block              uint64  `json:"block"`
	BlockHash          string  `json:"block_hash,omitempty"`
	Attribution        string  `json:"attribution"`
	Match              *bool   `json:"match,omitempty"`
	CumulativeDetected string  `json:"cumulative_detected"`
	CumulativeConf     string  `json:"cumulative_confirmed"`
	Remaining          string  `json:"remaining"`
	LastScanned        uint64  `json:"last_scanned"`
	TS                 string  `json:"ts,omitempty"`
}

type wireConfirming struct {
	V              int    `json:"v"`
	Event          string `json:"event"`
	TxHash         string `json:"tx_hash,omitempty"`
	Confirmations  uint64 `json:"confirmations"`
	Target         uint64 `json:"target"`
	CumulativeConf string `json:"cumulative_confirmed"`
	Remaining      string `json:"remaining"`
	LastScanned    uint64 `json:"last_scanned"`
	TS             string `json:"ts,omitempty"`
}

type wireConfirmed struct {
	V              int    `json:"v"`
	Event          string `json:"event"`
	TxHash         string `json:"tx_hash,omitempty"`
	Value          string `json:"value"`
	CumulativeConf string `json:"cumulative_confirmed"`
	Remaining      string `json:"remaining"`
	LastScanned    uint64 `json:"last_scanned"`
	TS             string `json:"ts,omitempty"`
}

type wireReorged struct {
	V              int    `json:"v"`
	Event          string `json:"event"`
	TxHash         string `json:"tx_hash,omitempty"`
	Value          string `json:"value"`
	CumulativeConf string `json:"cumulative_confirmed"`
	Remaining      string `json:"remaining"`
	LastScanned    uint64 `json:"last_scanned"`
	TS             string `json:"ts,omitempty"`
}

type wireHeartbeat struct {
	V              int    `json:"v"`
	Event          string `json:"event"`
	CumulativeConf string `json:"cumulative_confirmed"`
	Remaining      string `json:"remaining"`
	LastScanned    uint64 `json:"last_scanned"`
	TS             string `json:"ts,omitempty"`
}

type wireComplete struct {
	V              int      `json:"v"`
	Event          string   `json:"event"`
	CumulativeConf string   `json:"cumulative_confirmed"`
	TxHashes       []string `json:"tx_hashes,omitempty"`
	Address        string   `json:"address"`
	LastScanned    uint64   `json:"last_scanned"`
	Exit           int      `json:"exit"`
	TS             string   `json:"ts,omitempty"`
}

type wireTimeout struct {
	V              int    `json:"v"`
	Event          string `json:"event"`
	CumulativeConf string `json:"cumulative_confirmed"`
	Remaining      string `json:"remaining"`
	LastScanned    uint64 `json:"last_scanned"`
	Resume         string `json:"resume,omitempty"`
	Note           string `json:"note,omitempty"`
	Exit           int    `json:"exit"`
	TS             string `json:"ts,omitempty"`
}

// receiveJSONLine maps a domain.Event to its §5.8 NDJSON line. The bool is false
// for an event kind that is not part of the receive stream (skipped, never
// leaked). The marshaling never returns an error for these closed structs; a
// failure would be a programming bug and is dropped (the stream must not panic
// mid-listen).
func receiveJSONLine(ev domain.Event) ([]byte, bool) {
	switch ev.Kind {
	case domain.EvListening:
		w := wireListening{
			V:       1,
			Event:   string(ev.Kind),
			Address: ev.Address.Hex(),
			Network: ev.Network,
			ChainID: ev.ChainID,
			Asset:   assetFrom(ev.Asset),
			Target:  targetFrom(ev.TargetSpec),
			FromBlk: ev.FromBlock,
			TS:      ev.TS,
		}
		return marshalLine(w)
	case domain.EvDetected:
		w := wireDetected{
			V:                  1,
			Event:              string(ev.Kind),
			TxHash:             txHashPtr(ev.TxHash),
			LogIndex:           ev.LogIndex,
			From:               ev.From,
			Value:              defaultZero(ev.Value),
			TokenID:            ev.TokenID,
			Block:              ev.Block,
			BlockHash:          ev.BlockHash,
			Attribution:        ev.Attribution,
			Match:              ev.Match,
			CumulativeDetected: defaultZero(ev.CumulativeDetected),
			CumulativeConf:     defaultZero(ev.CumulativeConfirmed),
			Remaining:          defaultZero(ev.Remaining),
			LastScanned:        ev.LastScanned,
			TS:                 ev.TS,
		}
		return marshalLine(w)
	case domain.EvConfirming:
		w := wireConfirming{
			V:              1,
			Event:          string(ev.Kind),
			TxHash:         ev.TxHash,
			Confirmations:  ev.Conf,
			Target:         ev.Target,
			CumulativeConf: defaultZero(ev.CumulativeConfirmed),
			Remaining:      defaultZero(ev.Remaining),
			LastScanned:    ev.LastScanned,
			TS:             ev.TS,
		}
		return marshalLine(w)
	case domain.EvConfirmed:
		w := wireConfirmed{
			V:              1,
			Event:          string(ev.Kind),
			TxHash:         ev.TxHash,
			Value:          defaultZero(ev.Value),
			CumulativeConf: defaultZero(ev.CumulativeConfirmed),
			Remaining:      defaultZero(ev.Remaining),
			LastScanned:    ev.LastScanned,
			TS:             ev.TS,
		}
		return marshalLine(w)
	case domain.EvReorged:
		w := wireReorged{
			V:              1,
			Event:          string(ev.Kind),
			TxHash:         ev.TxHash,
			Value:          defaultZero(ev.Value),
			CumulativeConf: defaultZero(ev.CumulativeConfirmed),
			Remaining:      defaultZero(ev.Remaining),
			LastScanned:    ev.LastScanned,
			TS:             ev.TS,
		}
		return marshalLine(w)
	case domain.EvHeartbeat:
		w := wireHeartbeat{
			V:              1,
			Event:          string(ev.Kind),
			CumulativeConf: defaultZero(ev.CumulativeConfirmed),
			Remaining:      defaultZero(ev.Remaining),
			LastScanned:    ev.LastScanned,
			TS:             ev.TS,
		}
		return marshalLine(w)
	case domain.EvComplete:
		w := wireComplete{
			V:              1,
			Event:          string(ev.Kind),
			CumulativeConf: defaultZero(ev.CumulativeConfirmed),
			TxHashes:       ev.TxHashes,
			Address:        ev.Address.Hex(),
			LastScanned:    ev.LastScanned,
			Exit:           exitValue(ev.Exit),
			TS:             ev.TS,
		}
		return marshalLine(w)
	case domain.EvTimeout:
		w := wireTimeout{
			V:              1,
			Event:          string(ev.Kind),
			CumulativeConf: defaultZero(ev.CumulativeConfirmed),
			Remaining:      defaultZero(ev.Remaining),
			LastScanned:    ev.LastScanned,
			Resume:         ev.Resume,
			Note:           ev.Note,
			Exit:           exitValue(ev.Exit),
			TS:             ev.TS,
		}
		return marshalLine(w)
	default:
		// Not a receive-stream kind (a stray send/wait event); skip it so the
		// receive stdout stream stays pure NDJSON.
		return nil, false
	}
}

// receiveHumanLine renders one receive Event as a short human STDOUT line. The
// listening line leads with the address (the up-front share value). An
// unrecognized kind yields "" (skipped).
func receiveHumanLine(ev domain.Event) string {
	switch ev.Kind {
	case domain.EvListening:
		return "listening: " + ev.Address.Hex() + assetSuffix(ev.Asset)
	case domain.EvDetected:
		src := ev.Attribution
		if src == "" {
			src = "inbound"
		}
		return fmt.Sprintf("detected: %s value=%s (%s) cumulative-detected=%s remaining=%s",
			detectedRef(ev), defaultZero(ev.Value), src,
			defaultZero(ev.CumulativeDetected), defaultZero(ev.Remaining))
	case domain.EvConfirming:
		return fmt.Sprintf("confirming %d/%d: %s", ev.Conf, ev.Target, txOrInbound(ev.TxHash))
	case domain.EvConfirmed:
		return fmt.Sprintf("confirmed: %s value=%s cumulative-confirmed=%s remaining=%s",
			txOrInbound(ev.TxHash), defaultZero(ev.Value),
			defaultZero(ev.CumulativeConfirmed), defaultZero(ev.Remaining))
	case domain.EvReorged:
		return fmt.Sprintf("reorged: %s value=%s (subtracted) cumulative-confirmed=%s remaining=%s",
			txOrInbound(ev.TxHash), defaultZero(ev.Value),
			defaultZero(ev.CumulativeConfirmed), defaultZero(ev.Remaining))
	case domain.EvHeartbeat:
		return fmt.Sprintf("heartbeat: cumulative-confirmed=%s remaining=%s last-scanned=%d",
			defaultZero(ev.CumulativeConfirmed), defaultZero(ev.Remaining), ev.LastScanned)
	case domain.EvComplete:
		return fmt.Sprintf("complete: received %s (exit %d)",
			defaultZero(ev.CumulativeConfirmed), exitValue(ev.Exit))
	case domain.EvTimeout:
		line := fmt.Sprintf("timeout: received %s, remaining %s (exit %d)",
			defaultZero(ev.CumulativeConfirmed), defaultZero(ev.Remaining), exitValue(ev.Exit))
		if ev.Resume != "" {
			line += "\nresume: " + ev.Resume
		}
		return line
	default:
		return ""
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func marshalLine(v any) ([]byte, bool) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	return b, true
}

func assetFrom(a *domain.EventAsset) *wireAsset {
	if a == nil {
		return nil
	}
	return &wireAsset{
		Kind:     a.Kind,
		Contract: a.Contract,
		Alias:    a.Alias,
		Decimals: a.Decimals,
		TokenID:  a.TokenID,
	}
}

func targetFrom(t *domain.EventTarget) wireTargetSpec {
	if t == nil {
		// A listening line always has a target; an absent one still renders the
		// closed shape so the line is well-formed.
		return wireTargetSpec{Mode: string(domain.ModeAny)}
	}
	return wireTargetSpec{
		Mode:          t.Mode,
		Amount:        t.Amount,
		Confirmations: t.Confirmations,
		Timeout:       t.Timeout,
	}
}

// txHashPtr renders an empty tx hash as JSON null (the §5.8 balance-delta line is
// `"tx_hash":null`), and a present hash as the string.
func txHashPtr(h string) *string {
	if h == "" {
		return nil
	}
	return &h
}

// defaultZero renders an unset amount as "0" so an amount field is always a
// decimal string on the wire (never the empty string).
func defaultZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func exitValue(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func assetSuffix(a *domain.EventAsset) string {
	if a == nil || a.Kind == "" || a.Kind == "eth" {
		return ""
	}
	if a.Alias != "" {
		return " (" + a.Alias + ")"
	}
	if a.Contract != "" {
		return " (" + a.Contract + ")"
	}
	return " (" + a.Kind + ")"
}

func txOrInbound(h string) string {
	if h == "" {
		return "inbound"
	}
	return h
}

func detectedRef(ev domain.Event) string {
	if ev.TxHash != "" {
		return ev.TxHash
	}
	if ev.From != "" {
		return "from " + ev.From
	}
	return "inbound"
}
