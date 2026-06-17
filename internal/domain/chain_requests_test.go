package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// m2WireTypes is every M2 network/rpc/balance request/result struct. The
// reflective contract tests below run over this one list so a new M2 type is
// covered by adding a single line here (mirrors m1WireTypes).
func m2WireTypes() []any {
	return []any{
		// balance
		BalanceRequest{}, BalanceResult{},
		// network
		NetworkRow{}, NetworkAddRequest{}, NetworkUseRequest{},
		NetworkRemoveRequest{}, NetworkShowRequest{}, NetworkListRequest{},
		NetworkResult{}, NetworkListResult{}, NetworkRemoveResult{},
		// rpc
		RPCRow{}, RPCAddRequest{}, RPCUseRequest{}, RPCRenameRequest{},
		RPCRemoveRequest{}, RPCShowRequest{}, RPCListRequest{},
		RPCTestRequest{}, RPCTestResult{}, RPCResult{}, RPCListResult{},
		RPCRemoveResult{},
	}
}

// TestM2NoFloatOnWire reuses the §2.5 no-float invariant over the M2 types. A
// float anywhere (chain ids, wei, eth, latency are int/string) is a hard fail.
func TestM2NoFloatOnWire(t *testing.T) {
	for _, v := range m2WireTypes() {
		rt := reflect.TypeOf(v)
		assertNoFloat(t, rt, rt.Name())
	}
}

// TestM2WireFieldsHaveJSONTags: every exported field is on the wire (named json
// tag) or deliberately excluded (json:"-"). Catches an untagged exported field
// leaking under its Go name.
func TestM2WireFieldsHaveJSONTags(t *testing.T) {
	for _, v := range m2WireTypes() {
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.PkgPath != "" {
				continue
			}
			if _, ok := f.Tag.Lookup("json"); !ok {
				t.Errorf("%s.%s has no json tag; every exported wire field must be tagged (name or \"-\")",
					rt.Name(), f.Name)
			}
		}
	}
}

// TestM2WireFieldsAreStringSafe: user-VALUE scalars (wei, eth, addresses) are
// strings; only the deliberately-allowed non-string fields below may be integers.
// chain-id (uint64) and confirmations (uint) are IDENTIFIERS/counts bounded well
// within range, not uint256 values, so the plan (§5) types them as integers — the
// M1 walkWireFields helper hard-rejects any wide integer, so this test uses its
// own walk that honors the allow-list for uint64/uint/int64 too. A field NOT on
// this list that is any integer fails, so a future money field cannot slip in.
func TestM2WireFieldsAreStringSafe(t *testing.T) {
	allowedNonString := map[string]bool{
		// uint64 chain ids: an identifier (max ~2^53 in practice), not a value.
		"NetworkRow.chain_id":        true,
		"NetworkAddRequest.chain_id": true,
		"RPCTestResult.chain_id":     true,
		// uint confirmations count.
		"NetworkRow.confirmations": true,
		// int64 latency in ms.
		"RPCTestResult.latency_ms": true,
	}
	for _, v := range m2WireTypes() {
		rt := reflect.TypeOf(v)
		walkM2WireFields(t, rt, rt.Name(), allowedNonString)
	}
}

// walkM2WireFields is walkWireFields with the allow-list applied to ALL integer
// widths (the M1 helper only consults it for uint32/int). Strings, bools and
// nested structs are fine; any integer field must be on the allow-list.
func walkM2WireFields(t *testing.T, rt reflect.Type, typeName string, allowed map[string]bool) {
	t.Helper()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "-" || name == "" {
			continue // not on the wire
		}
		key := typeName + "." + name
		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Map {
			ft = ft.Elem()
		}
		switch ft.Kind() {
		case reflect.String, reflect.Bool, reflect.Struct:
			// strings + bools fine; nested structs recurse via m2WireTypes membership
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if !allowed[key] {
				t.Errorf("wire field %s is an integer %s but not on the allow-list; user VALUES must be strings (§2.5)", key, ft.Kind())
			}
		}
	}
}

// TestBalanceResultRoundTrip pins the §2.5 string wire form: wei/eth are exact
// decimal strings that survive marshal→unmarshal byte-for-byte.
func TestBalanceResultRoundTrip(t *testing.T) {
	in := BalanceResult{
		Address: "0x52908400098527886E0F7030069857D2E4169EE7",
		Network: "mainnet",
		Wei:     "1234567890123456789012345678901234567890", // larger than int64
		Eth:     "1234567890123456789012.34567890123456789",
		Symbol:  "ETH",
		Account: "treasury/0",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out BalanceResult
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n in = %+v\nout = %+v", in, out)
	}
	// The wei string must appear verbatim (no float coercion, no scientific form).
	if !strings.Contains(string(b), `"wei":"1234567890123456789012345678901234567890"`) {
		t.Fatalf("wei not preserved as an exact string: %s", b)
	}
}

// TestRPCAddRequestDurationWire pins the Duration field's string wire form.
func TestRPCAddRequestDurationWire(t *testing.T) {
	in := RPCAddRequest{Name: "corp-node", Network: "mainnet", URL: "https://x", Timeout: Duration{D: 5_000_000_000}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"timeout":"5s"`) {
		t.Fatalf("timeout did not marshal as a duration string: %s", b)
	}
	var out RPCAddRequest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Timeout.D != in.Timeout.D {
		t.Fatalf("timeout round-trip: got %v want %v", out.Timeout.D, in.Timeout.D)
	}
}

// TestM2CodeExitProjections pins the §5.7 exit projection of every new M2 code so
// the registry contract cannot drift.
func TestM2CodeExitProjections(t *testing.T) {
	cases := []struct {
		code string
		want ExitCode
	}{
		{CodeRPCChainIDMismatch, ExitIntegrity},  // 12
		{CodeRPCUnreachable, ExitNetwork},        // 6
		{CodeRPCUnsupported, ExitUsage},          // 2
		{CodeUsageUnsupported, ExitUsage},        // 2 (via usage prefix)
		{CodeUsageRPCNetworkMismatch, ExitUsage}, // 2
		{CodeUsageNetworkExists, ExitUsage},      // 2
		{CodeUsageRPCExists, ExitUsage},          // 2
		{CodeUsageBuiltinImmutable, ExitUsage},   // 2
		{CodeUsageNetworkInUse, ExitUsage},       // 2
		{CodeUsageLiteralSecret, ExitUsage},      // 2
	}
	for _, c := range cases {
		if got := ExitOf(c.code); got != c.want {
			t.Errorf("ExitOf(%q) = %d, want %d", c.code, got, c.want)
		}
	}
}

// TestRPCUnreachableRetryable: rpc.unreachable inherits the retryable hint (the
// agent send-loop branches on it).
func TestRPCUnreachableRetryable(t *testing.T) {
	e := New(CodeRPCUnreachable, "down")
	if !e.Retryable {
		t.Fatalf("rpc.unreachable should be retryable")
	}
}
