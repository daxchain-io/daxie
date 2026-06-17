package abi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	gethabi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Codec is the stateless ABI codec (§2.1). Value receiver; no state, so a single
// zero value serves every network and every concurrent request — the contract-verb
// analogue of erc.Ops. Service holds a bare abi.Codec.
type Codec struct{}

// DecodedValue is one labeled output/decoded arg. Value is ALWAYS a string (a
// uint256 exceeds int64; it is a decimal string, never a number — §2.5; arrays /
// tuples are JSON-encoded). It mirrors domain.DecodedValue field-for-field; service
// maps it 1:1 onto the wire type (the alias keeps abi free of a dependency on the
// domain wire-result struct while staying byte-compatible). NO float field (§2.5).
type DecodedValue = struct {
	Name  string `json:"name,omitempty"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ── typed errors (usage class → exit 2; the caller pointed at bad input) ─────────

// errBadABI is an invalid Solidity ABI JSON array (at `contract add` reject-before-
// store, and defensively on read).
func errBadABI(cause error) error {
	return domain.Wrap("usage.bad_abi", "invalid contract ABI JSON: "+causeMsg(cause), cause)
}

// errBadSig is a malformed inline human-readable signature (--sig).
func errBadSig(sig string, cause error) error {
	return domain.Wrap("usage.bad_sig", fmt.Sprintf("invalid signature %q: %s", sig, causeMsg(cause)), cause)
}

// errUnknownMethod is a method/event name not present in the resolved ABI.
func errUnknownMethod(name string) error {
	return domain.Newf("usage.unknown_method", "method or event %q is not in the ABI", name)
}

// errNoOutputs is a `contract call` whose method declares no return types (§2.5:
// call requires outputs).
func errNoOutputs(method string) error {
	return domain.Newf("usage.no_outputs", "method %q declares no return values; `call` needs return types (use --sig \"%s(…)(outputs)\")", method, method)
}

// errUnknownSelector is `contract decode` calldata whose leading selector matches
// no method in the resolved ABI.
func errUnknownSelector(sel string) error {
	return domain.Newf("usage.unknown_selector", "calldata selector %s is not in the ABI", sel)
}

// errBadCalldata is `contract decode` input that is not a 0x byte string or is
// shorter than the 4-byte selector.
func errBadCalldata(msg string) error {
	return domain.New("usage.bad_calldata", "invalid calldata: "+msg)
}

func causeMsg(err error) string {
	if err == nil {
		return "unknown error"
	}
	return err.Error()
}

// ── ABI parsing (the two resolution sources; §2.5 ABISource precedence) ──────────

// ParseJSON parses a canonical Solidity ABI JSON array into a *gethabi.ABI. It is
// the registry-stored-ABI + --abi/--abi-stdin source. An invalid ABI is
// usage.bad_abi (exit 2) — used both at `contract add` (reject before store) and on
// read. An empty document is rejected (an empty ABI cannot resolve any method).
func (Codec) ParseJSON(abiJSON []byte) (*gethabi.ABI, error) {
	if len(bytes.TrimSpace(abiJSON)) == 0 {
		return nil, errBadABI(fmt.Errorf("empty ABI document"))
	}
	parsed, err := gethabi.JSON(bytes.NewReader(abiJSON))
	if err != nil {
		return nil, errBadABI(err)
	}
	if len(parsed.Methods) == 0 && len(parsed.Events) == 0 {
		return nil, errBadABI(fmt.Errorf("ABI declares no methods or events"))
	}
	return &parsed, nil
}

// ParseSig parses an inline human-readable signature into a one-method-or-one-event
// ABI. It accepts cast's forms:
//
//   - "earned(address)"                          inputs only (send/encode/logs)
//   - "earned(address)(uint256)"                 inputs + outputs (call)
//   - "latestRoundData()(uint80,int256,uint256)" no inputs, multi-output
//   - "Staked(address indexed,uint256)"          event ("indexed" honored)
//   - named params are accepted ("transfer(address to,uint256 amount)")
//
// Unnamed inputs get positional names ("arg0", "arg1"); unnamed outputs likewise.
// Whether the signature is a method or an event is decided by the caller's context
// in general, but ParseSig reports isEvent so the caller need not pass --method when
// --sig carries it: a signature with an "indexed" param OR an uppercase-initial name
// is treated as an event; otherwise a method. (Both are emitted into the ABI under
// the SAME name, so UnpackLog/PackEvent resolve the event and PackCall the method.)
// A malformed signature is usage.bad_sig (exit 2).
func (Codec) ParseSig(sig string) (parsed *gethabi.ABI, name string, isEvent bool, err error) {
	name, inputs, outputs, hasOutputs, anyIndexed, perr := parseSignature(sig)
	if perr != nil {
		return nil, "", false, errBadSig(sig, perr)
	}

	// An event when it carries `indexed` params or its name begins with an
	// uppercase letter (the Solidity convention cast/foundry rely on for event vs
	// function disambiguation when only a signature is given). A method otherwise.
	isEvent = anyIndexed || (name != "" && name[0] >= 'A' && name[0] <= 'Z')

	// Build the in-memory ABI directly so we keep full control of names/indexed/
	// outputs (geth's ParseSelector cannot express outputs, named params, or
	// `indexed`). We construct the JSON document and hand it to gethabi.JSON.
	var entry abiJSONEntry
	entry.Name = name
	entry.Inputs = inputs
	if isEvent {
		entry.Type = "event"
		// An event carries no outputs; reject an (outputs) suffix on an event.
		if hasOutputs {
			return nil, "", false, errBadSig(sig, fmt.Errorf("an event signature must not declare outputs"))
		}
	} else {
		entry.Type = "function"
		entry.StateMutability = "nonpayable"
		if hasOutputs {
			entry.Outputs = outputs
		}
	}

	doc, merr := json.Marshal([]abiJSONEntry{entry})
	if merr != nil {
		return nil, "", false, errBadSig(sig, merr)
	}
	a, jerr := gethabi.JSON(bytes.NewReader(doc))
	if jerr != nil {
		return nil, "", false, errBadSig(sig, jerr)
	}
	return &a, name, isEvent, nil
}

// abiJSONEntry / abiJSONArg are the minimal Solidity-ABI JSON shape ParseSig emits
// for gethabi.JSON to consume (it understands tuple components, indexed, outputs).
type abiJSONEntry struct {
	Type            string       `json:"type"`
	Name            string       `json:"name"`
	Inputs          []abiJSONArg `json:"inputs"`
	Outputs         []abiJSONArg `json:"outputs,omitempty"`
	StateMutability string       `json:"stateMutability,omitempty"`
}

type abiJSONArg struct {
	Name         string       `json:"name"`
	Type         string       `json:"type"`
	InternalType string       `json:"internalType,omitempty"`
	Components   []abiJSONArg `json:"components,omitempty"`
	Indexed      bool         `json:"indexed,omitempty"`
}

// ── pack / unpack ────────────────────────────────────────────────────────────────

// PackCall builds selector||abi(coercedArgs) for method (the `contract send` data
// field + `contract encode` output). coercedArgs come from CoerceArgs (native Go
// values matching the declared input types). The golden test pins the bytes against
// cast for representative methods. An unknown method is usage.unknown_method.
func (Codec) PackCall(parsed *gethabi.ABI, method string, coercedArgs []any) ([]byte, error) {
	m, ok := parsed.Methods[method]
	if !ok {
		return nil, errUnknownMethod(method)
	}
	data, err := parsed.Pack(m.Name, coercedArgs...)
	if err != nil {
		// A pack failure here is an arg/shape mismatch the coercer did not catch
		// (e.g. a tuple component count): caller input → usage class.
		return nil, domain.Wrap("usage.bad_arg", "failed to encode call args: "+err.Error(), err)
	}
	return data, nil
}

// UnpackReturns decodes eth_call return bytes into labeled DecodedValue[] (one per
// ABI output). `call` requires the method to declare outputs (usage.no_outputs if
// not). Each value is formatted to a string (uint256 > int64 → decimal; arrays /
// tuples → JSON) — NO float (§2.5).
func (Codec) UnpackReturns(parsed *gethabi.ABI, method string, ret []byte) ([]DecodedValue, error) {
	m, ok := parsed.Methods[method]
	if !ok {
		return nil, errUnknownMethod(method)
	}
	if len(m.Outputs) == 0 {
		return nil, errNoOutputs(method)
	}
	vals, err := m.Outputs.Unpack(ret)
	if err != nil {
		return nil, domain.Wrap("tx.reverted", "failed to decode return data: "+err.Error(), err)
	}
	return labelValues(m.Outputs, vals), nil
}

// UnpackCalldata decodes selector||args (the `contract decode` path): it reads the
// leading 4-byte selector, resolves the method on the ABI (usage.unknown_selector
// if no match), and decodes the args to labeled DecodedValue[]. Pure — no chain,
// never policy (§11 D12). A short / non-hex calldata is usage.bad_calldata.
func (Codec) UnpackCalldata(parsed *gethabi.ABI, calldata []byte) (method, selectorHex string, args []DecodedValue, err error) {
	if len(calldata) < 4 {
		return "", "", nil, errBadCalldata("shorter than the 4-byte selector")
	}
	sel := calldata[:4]
	selectorHex = "0x" + hex.EncodeToString(sel)
	m, merr := parsed.MethodById(sel)
	if merr != nil {
		return "", "", nil, errUnknownSelector(selectorHex)
	}
	vals, uerr := m.Inputs.Unpack(calldata[4:])
	if uerr != nil {
		return "", "", nil, domain.Wrap("usage.bad_calldata", "failed to decode call args: "+uerr.Error(), uerr)
	}
	return m.Name, selectorHex, labelValues(m.Inputs, vals), nil
}

// ── events (logs) ────────────────────────────────────────────────────────────────

// EventTopic0 returns keccak(eventSignature) — the canonical Topics[0] for the
// event. An unknown event is usage.unknown_method.
func (Codec) EventTopic0(parsed *gethabi.ABI, event string) (common.Hash, error) {
	ev, ok := parsed.Events[event]
	if !ok {
		return common.Hash{}, errUnknownMethod(event)
	}
	return ev.ID, nil
}

// PackEvent builds the eth_getLogs Topics for `contract logs`: Topics[0] =
// keccak(event signature); each indexed-arg filter → the positional Topics[i] word
// (address-typed filter values are common.Address; the caller ref/ENS-resolves them
// before this call). A filter naming a NON-indexed arg is usage.bad_arg (exit 2).
// Returns [][]common.Hash (the geth FilterQuery.Topics shape) + Topics[0].
//
// filters maps an indexed arg NAME → its coerced value (the native Go value
// MakeTopics consumes: common.Address, *big.Int, bool, [N]byte, etc.). A name not
// in the event, or a name on a non-indexed arg, is usage.bad_arg.
func (Codec) PackEvent(parsed *gethabi.ABI, event string, filters map[string]any) ([][]common.Hash, common.Hash, error) {
	ev, ok := parsed.Events[event]
	if !ok {
		return nil, common.Hash{}, errUnknownMethod(event)
	}

	// Position 0 is the signature topic; indexed args occupy positions 1..N in ABI
	// order. Build a per-position query slice that MakeTopics turns into topics.

	// Validate every filter name is an INDEXED arg in this event.
	for name := range filters {
		matched := false
		for _, in := range ev.Inputs {
			if in.Name == name {
				matched = true
				if !in.Indexed {
					return nil, common.Hash{}, domain.Newf("usage.bad_arg", "event arg %q is not indexed and cannot be filtered", name)
				}
				break
			}
		}
		if !matched {
			return nil, common.Hash{}, domain.Newf("usage.bad_arg", "event %q has no arg named %q", event, name)
		}
	}

	// query[0] is the signature topic; query[i+1] holds the i-th indexed arg's
	// filter (empty = wildcard at that position).
	var indexedArgs gethabi.Arguments
	for _, in := range ev.Inputs {
		if in.Indexed {
			indexedArgs = append(indexedArgs, in)
		}
	}
	query := make([][]any, len(indexedArgs)+1)
	query[0] = []any{ev.ID}
	for i, in := range indexedArgs {
		if v, ok := filters[in.Name]; ok {
			query[i+1] = []any{v}
		}
	}
	topics, err := gethabi.MakeTopics(query...)
	if err != nil {
		return nil, common.Hash{}, domain.Wrap("usage.bad_arg", "failed to build event topic filter: "+err.Error(), err)
	}
	return topics, ev.ID, nil
}

// UnpackLog decodes one log (topics + data) against the event ABI into labeled
// DecodedValue[]: indexed args reconstructed from Topics[1:], non-indexed args from
// Data, merged in ABI declaration order. Backs `contract logs` per-log decode. A
// dynamic indexed arg (string/bytes/array/tuple) cannot be reconstructed from its
// topic (only its keccak hash is on-chain) — its value is rendered as the 0x topic
// hash, the most faithful representation available (matching cast).
func (Codec) UnpackLog(parsed *gethabi.ABI, event string, topics []common.Hash, data []byte) ([]DecodedValue, error) {
	ev, ok := parsed.Events[event]
	if !ok {
		return nil, errUnknownMethod(event)
	}

	// Non-indexed args from Data.
	nonIndexed := ev.Inputs.NonIndexed()
	dataVals := make(map[string]any, len(nonIndexed))
	if len(nonIndexed) > 0 {
		if err := ev.Inputs.UnpackIntoMap(dataVals, data); err != nil {
			return nil, domain.Wrap("usage.bad_calldata", "failed to decode log data: "+err.Error(), err)
		}
	}

	// Indexed args from Topics[1:] (Topics[0] is the signature).
	indexedVals := make(map[string]any)
	var indexedArgs gethabi.Arguments
	for _, in := range ev.Inputs {
		if in.Indexed {
			indexedArgs = append(indexedArgs, in)
		}
	}
	if len(indexedArgs) > 0 {
		if len(topics) < 1+len(indexedArgs) {
			return nil, domain.New("usage.bad_calldata", "log has fewer topics than the event declares indexed args")
		}
		if err := gethabi.ParseTopicsIntoMap(indexedVals, indexedArgs, topics[1:1+len(indexedArgs)]); err != nil {
			return nil, domain.Wrap("usage.bad_calldata", "failed to decode indexed log args: "+err.Error(), err)
		}
	}

	// Merge in ABI declaration order so the output reads naturally.
	out := make([]DecodedValue, 0, len(ev.Inputs))
	for _, in := range ev.Inputs {
		var v any
		if in.Indexed {
			v = indexedVals[in.Name]
		} else {
			v = dataVals[in.Name]
		}
		out = append(out, DecodedValue{
			Name:  in.Name,
			Type:  in.Type.String(),
			Value: formatValue(v),
		})
	}
	return out, nil
}

// ── value labeling / formatting (every value to a string; NO float, §2.5) ────────

// labelValues pairs each unpacked value with its declared Argument (name + solidity
// type), formatting the value to a string.
func labelValues(args gethabi.Arguments, vals []any) []DecodedValue {
	out := make([]DecodedValue, 0, len(args))
	for i, a := range args {
		var v any
		if i < len(vals) {
			v = vals[i]
		}
		out = append(out, DecodedValue{
			Name:  a.Name,
			Type:  a.Type.String(),
			Value: formatValue(v),
		})
	}
	return out
}

// formatValue renders a decoded ABI value as a string WITHOUT float arithmetic.
// Scalars get their natural string form (uint256 → decimal, address → checksummed
// 0x, bytes → 0x hex, bool → true/false); compound values (slices, arrays, structs)
// → a JSON encoding. This is the one place the "every value is a string, never a
// float" rule (§2.5) is enforced for the decode/return paths.
func formatValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case *big.Int:
		if t == nil {
			return ""
		}
		return t.String()
	case big.Int:
		return t.String()
	case common.Address:
		return t.Hex()
	case common.Hash:
		return t.Hex()
	case bool:
		if t {
			return "true"
		}
		return "false"
	case string:
		return t
	case []byte:
		return "0x" + hex.EncodeToString(t)
	default:
		return formatComposite(v)
	}
}

// formatComposite renders fixed-bytes, slices, arrays and tuples (structs) to a
// stable string. Fixed-byte arrays ([N]byte) → 0x hex; everything else → JSON via a
// recursive normalizer that keeps integers/addresses/bytes as strings (so a uint256
// element never crosses as a JSON number that would lose precision).
func formatComposite(v any) string {
	norm := normalizeForJSON(v)
	b, err := json.Marshal(norm)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// normalizeForJSON recursively converts a decoded ABI value into a JSON-safe shape:
// big integers and fixed-bytes become strings; slices/arrays become []any; structs
// (tuples) become an ordered []any of their field values (positional — the labeled
// outer name carries the tuple's solidity type). Using reflection keeps it generic
// across the arbitrary nested types geth's Unpack returns.
func normalizeForJSON(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case *big.Int:
		if t == nil {
			return nil
		}
		return t.String()
	case big.Int:
		return t.String()
	case common.Address:
		return t.Hex()
	case common.Hash:
		return t.Hex()
	case bool:
		return t
	case string:
		return t
	case []byte:
		return "0x" + hex.EncodeToString(t)
	}
	return normalizeReflect(v)
}

// the reflection tail for slices, arrays (incl. fixed-byte arrays) and structs.
func normalizeReflect(v any) any {
	rv := reflectValueOf(v)
	switch rv.kind {
	case kindFixedBytes:
		return "0x" + hex.EncodeToString(rv.bytes)
	case kindSliceOrArray:
		out := make([]any, 0, len(rv.elems))
		for _, e := range rv.elems {
			out = append(out, normalizeForJSON(e))
		}
		return out
	case kindStruct:
		out := make([]any, 0, len(rv.elems))
		for _, e := range rv.elems {
			out = append(out, normalizeForJSON(e))
		}
		return out
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ── signature grammar parser (cast forms) ─────────────────────────────────────────

// parseSignature parses a cast-style signature into (name, inputs, outputs,
// hasOutputs, anyIndexed). It is a small recursive-descent parser over the type
// grammar so it can support what geth's ParseSelector cannot: named params, the
// `indexed` keyword (events), and the trailing (outputs) tuple (call). The type
// strings it produces (e.g. "uint256", "address[]", "tuple") + components feed
// gethabi.JSON, which is the authoritative type compiler.
func parseSignature(sig string) (name string, inputs, outputs []abiJSONArg, hasOutputs, anyIndexed bool, err error) {
	s := strings.TrimSpace(sig)
	p := &sigParser{s: s}

	name, err = p.identifier()
	if err != nil {
		return "", nil, nil, false, false, err
	}
	if !p.consume('(') {
		return "", nil, nil, false, false, fmt.Errorf("expected '(' after name")
	}
	inputs, anyIndexed, err = p.argList(true)
	if err != nil {
		return "", nil, nil, false, false, err
	}
	if !p.consume(')') {
		return "", nil, nil, false, false, fmt.Errorf("expected ')' closing inputs")
	}

	p.skipSpace()
	if p.peek() == '(' {
		p.consume('(')
		var anyIdxOut bool
		outputs, anyIdxOut, err = p.argList(false)
		if err != nil {
			return "", nil, nil, false, false, err
		}
		if anyIdxOut {
			return "", nil, nil, false, false, fmt.Errorf("outputs cannot be 'indexed'")
		}
		if !p.consume(')') {
			return "", nil, nil, false, false, fmt.Errorf("expected ')' closing outputs")
		}
		hasOutputs = true
	}

	p.skipSpace()
	if !p.eof() {
		return "", nil, nil, false, false, fmt.Errorf("unexpected trailing text %q", p.rest())
	}

	// Assign positional names to any unnamed arg (recursively into tuple
	// components). gethabi.JSON builds a reflect.StructOf for every tuple and PANICS
	// on an anonymous field, so every component MUST be named; unnamed top-level
	// params get "arg0","arg1",… so the decode output is still labeled.
	nameArgs(inputs, "arg")
	nameArgs(outputs, "ret")

	return name, inputs, outputs, hasOutputs, anyIndexed, nil
}

// nameArgs fills any empty arg name with prefix+index and recurses into tuple
// components (whose components must ALSO be named — geth panics otherwise). Tuple
// components are always named "field0","field1",… when unnamed, regardless of the
// outer prefix, so a nested decode is labeled too.
func nameArgs(args []abiJSONArg, prefix string) {
	for i := range args {
		if args[i].Name == "" {
			args[i].Name = fmt.Sprintf("%s%d", prefix, i)
		}
		if len(args[i].Components) > 0 {
			nameArgs(args[i].Components, "field")
		}
	}
}

type sigParser struct {
	s string
	i int
}

func (p *sigParser) eof() bool    { return p.i >= len(p.s) }
func (p *sigParser) rest() string { return p.s[p.i:] }
func (p *sigParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.i]
}

func (p *sigParser) skipSpace() {
	for !p.eof() && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *sigParser) consume(c byte) bool {
	p.skipSpace()
	if !p.eof() && p.s[p.i] == c {
		p.i++
		return true
	}
	return false
}

// identifier reads a Solidity identifier (letters/digits/_/$, not starting with a
// digit). An empty/invalid identifier is an error.
func (p *sigParser) identifier() (string, error) {
	p.skipSpace()
	start := p.i
	if p.eof() {
		return "", fmt.Errorf("expected a name")
	}
	c := p.s[p.i]
	if !isAlpha(c) && c != '_' && c != '$' {
		return "", fmt.Errorf("invalid name start %q", string(c))
	}
	p.i++
	for !p.eof() {
		c = p.s[p.i]
		if isAlpha(c) || isDigit(c) || c == '_' || c == '$' {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i], nil
}

// argList parses a comma-separated list of args until (but not consuming) the
// closing ')'. allowIndexed permits the `indexed` keyword (events). An empty list
// ("()") is valid. Returns the args + whether any was indexed.
func (p *sigParser) argList(allowIndexed bool) ([]abiJSONArg, bool, error) {
	var out []abiJSONArg
	anyIndexed := false
	p.skipSpace()
	if p.peek() == ')' {
		return out, false, nil // empty list
	}
	for {
		arg, idx, err := p.arg(allowIndexed)
		if err != nil {
			return nil, false, err
		}
		if idx {
			anyIndexed = true
		}
		out = append(out, arg)
		p.skipSpace()
		if p.peek() == ',' {
			p.i++
			continue
		}
		break
	}
	return out, anyIndexed, nil
}

// arg parses one argument: a type (elementary OR a tuple "(...)" with optional [N]
// array suffix), then an optional `indexed` keyword, then an optional name.
func (p *sigParser) arg(allowIndexed bool) (abiJSONArg, bool, error) {
	p.skipSpace()
	var a abiJSONArg

	if p.peek() == '(' {
		// Tuple: parse the component list recursively.
		p.consume('(')
		comps, _, err := p.argList(false) // tuple components cannot be indexed
		if err != nil {
			return a, false, err
		}
		if !p.consume(')') {
			return a, false, fmt.Errorf("expected ')' closing a tuple")
		}
		a.Components = comps
		// Optional array suffix(es) on the tuple, e.g. "(uint256,uint256)[]".
		suffix, err := p.arraySuffix()
		if err != nil {
			return a, false, err
		}
		a.Type = "tuple" + suffix
		a.InternalType = a.Type
	} else {
		// Elementary type token, possibly with array suffix(es).
		tok, err := p.typeToken()
		if err != nil {
			return a, false, err
		}
		a.Type = tok
		a.InternalType = tok
	}

	// Optional `indexed` keyword, then optional name. The two tokens after a type
	// are read in order: if the first is exactly "indexed" (and allowed) it sets
	// the flag; any remaining identifier is the param name.
	idx := false
	p.skipSpace()
	if id, ok := p.maybeIdentifier(); ok {
		if id == "indexed" {
			if !allowIndexed {
				return a, false, fmt.Errorf("'indexed' is only valid on event args")
			}
			idx = true
			a.Indexed = true
			// A name may still follow the indexed keyword.
			p.skipSpace()
			if name2, ok2 := p.maybeIdentifier(); ok2 {
				a.Name = name2
			}
		} else {
			a.Name = id
		}
	}
	return a, idx, nil
}

// typeToken reads an elementary type token plus any array suffix(es). It does NOT
// validate the base type name — gethabi.JSON does that authoritatively when the ABI
// is compiled, so an unknown type surfaces as usage.bad_sig there.
func (p *sigParser) typeToken() (string, error) {
	p.skipSpace()
	start := p.i
	if p.eof() {
		return "", fmt.Errorf("expected a type")
	}
	c := p.s[p.i]
	if !isAlpha(c) {
		return "", fmt.Errorf("invalid type start %q", string(c))
	}
	p.i++
	for !p.eof() {
		c = p.s[p.i]
		if isAlpha(c) || isDigit(c) {
			p.i++
			continue
		}
		break
	}
	base := p.s[start:p.i]
	suffix, err := p.arraySuffix()
	if err != nil {
		return "", err
	}
	return base + suffix, nil
}

// arraySuffix reads zero or more array suffixes: "[]" (dynamic) or "[N]" (fixed).
func (p *sigParser) arraySuffix() (string, error) {
	var sb strings.Builder
	for p.peek() == '[' {
		p.i++ // consume '['
		sb.WriteByte('[')
		for !p.eof() && isDigit(p.s[p.i]) {
			sb.WriteByte(p.s[p.i])
			p.i++
		}
		if p.peek() != ']' {
			return "", fmt.Errorf("expected ']' closing an array type")
		}
		p.i++ // consume ']'
		sb.WriteByte(']')
	}
	return sb.String(), nil
}

// maybeIdentifier reads an identifier if one is present at the cursor (used for the
// optional `indexed` keyword + the optional param name).
func (p *sigParser) maybeIdentifier() (string, bool) {
	p.skipSpace()
	if p.eof() {
		return "", false
	}
	c := p.s[p.i]
	if !isAlpha(c) && c != '_' && c != '$' {
		return "", false
	}
	start := p.i
	p.i++
	for !p.eof() {
		c = p.s[p.i]
		if isAlpha(c) || isDigit(c) || c == '_' || c == '$' {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i], true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// ── reflection helper for formatting compound decoded values ──────────────────────

// reflectKind classifies a reflected value for the JSON normalizer.
type reflectKind int

const (
	kindOther reflectKind = iota
	kindFixedBytes
	kindSliceOrArray
	kindStruct
)

// reflectView is the minimal projection normalizeReflect needs: the kind plus the
// extracted bytes (fixed-byte arrays) or element values (slices/arrays/structs).
type reflectView struct {
	kind  reflectKind
	bytes []byte
	elems []any
}

// reflectValueOf inspects v via reflection and projects it into a reflectView. It
// handles the value types geth's Unpack emits for compound ABI types:
//
//   - [N]byte (FixedBytesTy) → kindFixedBytes (rendered as 0x hex);
//   - []T / [N]T              → kindSliceOrArray (recursed element-by-element);
//   - struct (tuple)          → kindStruct (recursed field-by-field, in order).
func reflectValueOf(v any) reflectView {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return reflectView{kind: kindOther}
	}
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return reflectView{kind: kindOther}
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				// Each element is a uint8 ([N]byte), always in [0,255].
				b[i] = byte(rv.Index(i).Uint()) // #nosec G115 -- element kind is Uint8
			}
			return reflectView{kind: kindFixedBytes, bytes: b}
		}
		fallthrough
	case reflect.Slice:
		out := make([]any, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out = append(out, rv.Index(i).Interface())
		}
		return reflectView{kind: kindSliceOrArray, elems: out}
	case reflect.Struct:
		out := make([]any, 0, rv.NumField())
		for i := 0; i < rv.NumField(); i++ {
			f := rv.Field(i)
			if !f.CanInterface() {
				continue
			}
			out = append(out, f.Interface())
		}
		return reflectView{kind: kindStruct, elems: out}
	default:
		return reflectView{kind: kindOther}
	}
}
