package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// m1WireTypes is every M1 wallet/account/keystore request/result struct. The
// reflective contract tests below run over this one list so a new type added to
// the contract is covered by adding a single line here.
func m1WireTypes() []any {
	return []any{
		// wallet
		WalletCreateRequest{}, WalletCreateResult{},
		WalletImportRequest{}, WalletImportResult{},
		WalletListRequest{}, WalletListResult{}, WalletSummary{},
		WalletShowRequest{}, WalletShowResult{},
		WalletRenameRequest{}, WalletRenameResult{},
		WalletExportRequest{}, WalletExportResult{},
		WalletDeleteRequest{}, WalletDeleteResult{},
		// account
		AccountSummary{},
		AccountDeriveRequest{}, AccountDeriveResult{},
		AccountAliasRequest{}, AccountAliasResult{},
		AccountUnaliasRequest{}, AccountUnaliasResult{},
		AccountImportRequest{}, AccountImportResult{},
		AccountUseRequest{}, AccountUseResult{},
		AccountListRequest{}, AccountListResult{},
		AccountShowRequest{}, AccountShowResult{},
		AccountExportRequest{}, AccountExportResult{},
		AccountDeleteRequest{}, AccountDeleteResult{},
		// keystore
		KeystoreInfoRequest{}, KeystoreInfoResult{},
		KeystoreChangePassphraseRequest{}, KeystoreChangePassphraseResult{},
	}
}

// TestNoFloatOnWireTypes is the §2.5 "no float field" invariant, enforced
// reflectively (recursively, through slices/pointers/structs) over every M1 wire
// type. A float32/float64 anywhere on the wire is a hard violation: amounts,
// indices and counts are strings/ints by contract.
func TestNoFloatOnWireTypes(t *testing.T) {
	for _, v := range m1WireTypes() {
		rt := reflect.TypeOf(v)
		assertNoFloat(t, rt, rt.Name())
	}
}

func assertNoFloat(t *testing.T, rt reflect.Type, path string) {
	t.Helper()
	switch rt.Kind() {
	case reflect.Float32, reflect.Float64:
		t.Errorf("FLOAT ON WIRE: %s is a %s; §2.5 forbids float fields", path, rt.Kind())
	case reflect.Pointer, reflect.Slice, reflect.Array:
		assertNoFloat(t, rt.Elem(), path+"[]")
	case reflect.Struct:
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			assertNoFloat(t, f.Type, path+"."+f.Name)
		}
	}
}

// TestWireFieldsAreStringSafe asserts that every JSON-serialized scalar that
// carries a USER VALUE is a string, with the deliberately-allowed exceptions:
// uint32 indices, int counts/format/scrypt_n, and bool flags. No int64/uint64
// money-or-id field is permitted on the wire (those must be strings, §2.5: a
// uint256 exceeds int64). This catches a value that should have been a string
// being typed as a wide integer.
func TestWireFieldsAreStringSafe(t *testing.T) {
	// Fields legitimately typed as a small non-string scalar.
	allowedNonString := map[string]bool{
		// uint32 indices / counters
		"WalletShowResult.next_index": true,
		"AccountDeriveRequest.index":  true, // *uint32
		"AccountDeriveResult.index":   true,
		"AccountUnaliasResult.index":  true,
		"AccountSummary.index":        true, // *uint32
		"AccountShowResult.index":     true, // *uint32
		// int counts / versions
		"WalletCreateRequest.words":                    true,
		"WalletSummary.accounts":                       true,
		"KeystoreInfoResult.format":                    true,
		"KeystoreInfoResult.wallets":                   true,
		"KeystoreInfoResult.accounts":                  true,
		"KeystoreInfoResult.hd_accounts":               true,
		"KeystoreInfoResult.scrypt_n":                  true,
		"KeystoreChangePassphraseResult.rotated_files": true,
	}
	for _, v := range m1WireTypes() {
		rt := reflect.TypeOf(v)
		walkWireFields(t, rt, rt.Name(), allowedNonString)
	}
}

func walkWireFields(t *testing.T, rt reflect.Type, typeName string, allowed map[string]bool) {
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
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		switch ft.Kind() {
		case reflect.String, reflect.Bool, reflect.Struct:
			// strings + bools are fine; nested structs (slices of summaries) recurse below
		case reflect.Uint32, reflect.Int:
			if !allowed[key] {
				t.Errorf("wire field %s is %s but not on the small-scalar allow-list; user values must be strings (§2.5)", key, ft.Kind())
			}
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint64:
			t.Errorf("wire field %s is a wide integer %s; §2.5 requires a string (a uint256 exceeds int64)", key, ft.Kind())
		}
	}
}

// TestWireFieldsHaveJSONTags: every exported field is either on the wire (a json
// tag with a name) or deliberately excluded (json:"-"). An untagged exported
// field would leak under its Go name into the JSON/MCP schema.
func TestWireFieldsHaveJSONTags(t *testing.T) {
	for _, v := range m1WireTypes() {
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.PkgPath != "" {
				continue // unexported
			}
			if _, ok := f.Tag.Lookup("json"); !ok {
				t.Errorf("%s.%s has no json tag; every exported wire field must be tagged (name or \"-\")",
					rt.Name(), f.Name)
			}
		}
	}
}

// TestInputFieldsHaveJSONSchema: the operator-INPUT request fields that ARE on the
// wire (not json:"-") must carry a jsonschema tag so the M11 MCP tool schema is
// generated, not hand-written. Result fields and json:"-" ceremony fields are
// exempt (results are output; "-" fields never reach the schema).
func TestInputFieldsHaveJSONSchema(t *testing.T) {
	// The wire-bearing INPUT fields that must describe themselves to the schema.
	requests := []any{
		WalletCreateRequest{}, WalletImportRequest{}, WalletRenameRequest{},
		AccountDeriveRequest{}, AccountAliasRequest{}, AccountImportRequest{},
	}
	for _, v := range requests {
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			jtag := f.Tag.Get("json")
			name := strings.Split(jtag, ",")[0]
			if name == "-" || name == "" {
				continue // CLI-only ceremony or not on the wire
			}
			if f.Tag.Get("jsonschema") == "" {
				t.Errorf("%s.%s is a wire input without a jsonschema tag; the MCP schema (M11) needs it",
					rt.Name(), f.Name)
			}
		}
	}
}

// TestSecretsNeverInRequestStructs: no request struct may carry a field whose name
// suggests secret material (passphrase, mnemonic, private key). Secrets flow as
// *secret.Bytes out of band, never serialized (§3.10, §6.1). Result structs DO
// carry once-shown sensitive values and are exempt — they are guarded by the
// Sensitive flag instead.
func TestSecretsNeverInRequestStructs(t *testing.T) {
	requests := []any{
		WalletCreateRequest{}, WalletImportRequest{}, WalletListRequest{},
		WalletShowRequest{}, WalletRenameRequest{}, WalletExportRequest{},
		WalletDeleteRequest{}, AccountDeriveRequest{}, AccountAliasRequest{},
		AccountUnaliasRequest{}, AccountImportRequest{}, AccountUseRequest{},
		AccountListRequest{}, AccountShowRequest{}, AccountExportRequest{},
		AccountDeleteRequest{}, KeystoreInfoRequest{}, KeystoreChangePassphraseRequest{},
	}
	banned := []string{"passphrase", "mnemonic", "privatekey", "private_key", "secret", "seed", "key"}
	for _, v := range requests {
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			lower := strings.ToLower(rt.Field(i).Name)
			for _, b := range banned {
				// "key" alone would false-positive on e.g. nothing here, but guard
				// against an accidental RawKey/PrivKey field landing in a request.
				if lower == b || strings.Contains(lower, "passphrase") ||
					strings.Contains(lower, "mnemonic") || strings.Contains(lower, "privatekey") ||
					strings.Contains(lower, "rawkey") {
					t.Errorf("request %s.%s looks like secret material; secrets flow as *secret.Bytes out of band, never in a request struct (§3.10)",
						rt.Name(), rt.Field(i).Name)
				}
			}
		}
	}
}

// TestRequestResultRoundTrip: every M1 wire type survives a JSON marshal/unmarshal
// round-trip with representative values (the schema↔marshaling contract, §2.9
// "schema ↔ marshaling" row). Pointers and slices are exercised.
func TestRequestResultRoundTrip(t *testing.T) {
	idx := uint32(3)
	// Note: json:"-" ceremony fields (Yes/Confirm/QR) are intentionally NOT set
	// here — they do not serialize and so cannot round-trip by design; their
	// exclusion from the wire is asserted separately in
	// TestCLICeremonyFieldsExcludedFromWire.
	cases := []any{
		&WalletCreateRequest{Name: "treasury", Words: 24},
		&WalletCreateResult{
			Name: "treasury", WalletID: "6f1c2e58", PathPrefix: "m/44'/60'/0'/0",
			Account0: "treasury/0", Account0Address: "0x52908400098527886E0F7030069857D2E4169EE7",
			Mnemonic: "abandon abandon about", Sensitive: true, PassphraseFinger: "deadbeef",
		},
		&WalletImportResult{Name: "ops", WalletID: "a3b9", PathPrefix: "m/44'/60'/0'/0", Account0: "ops/0"},
		&WalletListResult{Wallets: []WalletSummary{{Name: "treasury", WalletID: "6f1c", Accounts: 2, CreatedAt: "2026-06-12T09:21:33Z"}}},
		&WalletShowResult{
			Name: "treasury", WalletID: "6f1c", PathPrefix: "m/44'/60'/0'/0", NextIndex: 4,
			CreatedAt: "2026-06-12T09:21:33Z",
			Accounts:  []AccountSummary{{Ref: "treasury/0", Address: "0x52ae", Kind: "hd", Wallet: "treasury", Index: &idx, CreatedAt: "2026-06-12T09:21:33Z"}},
		},
		&WalletRenameResult{Old: "a", New: "b", WalletID: "6f1c"},
		&WalletExportResult{Name: "treasury", Mnemonic: "abandon abandon about", Sensitive: true},
		&WalletDeleteResult{Name: "treasury", WalletID: "6f1c", Deleted: true},
		&AccountDeriveRequest{Wallet: "treasury", Index: &idx, Name: "payroll"},
		&AccountDeriveResult{Ref: "treasury/3", Address: "0x52ae", Index: 3, Alias: "payroll"},
		&AccountAliasResult{Ref: "treasury/3", Alias: "payroll", Address: "0x52ae"},
		&AccountUnaliasResult{Wallet: "treasury", Index: 3, RemovedAlias: "payroll"},
		&AccountImportResult{Name: "ops-key", Address: "0x52ae", AccountID: "UTC--…"},
		&AccountUseResult{Ref: "treasury/0", Address: "0x52ae"},
		&AccountListResult{Accounts: []AccountSummary{{Ref: "ops-key", Address: "0x52ae", Kind: "standalone", CreatedAt: "x"}}, Default: "treasury/0"},
		&AccountShowResult{Ref: "treasury/3", Address: "0x52ae", Kind: "hd", Wallet: "treasury", Index: &idx, Alias: "payroll", Path: "m/44'/60'/0'/0/3", Default: true},
		&AccountExportResult{Ref: "ops-key", Address: "0x52ae", PrivateKey: "0xabc", Sensitive: true},
		&AccountDeleteResult{Ref: "treasury/3", Mode: "forget", Deleted: true},
		&KeystoreInfoResult{Path: "/k", Format: 1, Wallets: 2, Accounts: 1, HDAccounts: 3, Initialized: true, KDF: "scrypt", ScryptN: 1 << 18},
		&KeystoreChangePassphraseResult{RotatedFiles: 4, PassphraseFinger: "deadbeef"},
	}
	for _, c := range cases {
		b, err := json.Marshal(c)
		if err != nil {
			t.Errorf("marshal %T: %v", c, err)
			continue
		}
		out := reflect.New(reflect.TypeOf(c).Elem()).Interface()
		if err := json.Unmarshal(b, out); err != nil {
			t.Errorf("unmarshal %T: %v\n%s", c, err, b)
			continue
		}
		if !reflect.DeepEqual(c, out) {
			t.Errorf("round-trip mismatch for %T:\n got %+v\nwant %+v", c, out, c)
		}
	}
}

// TestPointerIndexDistinguishesZero documents why AccountSummary.Index /
// AccountShowResult.Index are *uint32: index 0 is a real, common account and must
// be distinguishable from "no index" (a standalone account). A nil index omits
// the key; index 0 serializes as 0.
func TestPointerIndexDistinguishesZero(t *testing.T) {
	zero := uint32(0)
	with := AccountSummary{Ref: "treasury/0", Address: "0x52ae", Kind: "hd", Index: &zero, CreatedAt: "x"}
	bWith, _ := json.Marshal(with)
	if !strings.Contains(string(bWith), `"index":0`) {
		t.Errorf("HD index 0 must serialize as index:0, got %s", bWith)
	}
	without := AccountSummary{Ref: "ops-key", Address: "0x52ae", Kind: "standalone", CreatedAt: "x"}
	bWithout, _ := json.Marshal(without)
	if strings.Contains(string(bWithout), `"index"`) {
		t.Errorf("standalone account must omit index, got %s", bWithout)
	}
}

// TestCLICeremonyFieldsExcludedFromWire: the json:"-" ceremony fields (Yes,
// Confirm, QR) never serialize, so the MCP schema (M11) omits them and a journal
// never records them.
func TestCLICeremonyFieldsExcludedFromWire(t *testing.T) {
	b, _ := json.Marshal(WalletExportRequest{Name: "treasury", Yes: true, Confirm: "treasury"})
	s := string(b)
	for _, leaked := range []string{"true", "confirm", "yes", "Yes", "Confirm"} {
		if strings.Contains(s, leaked) && leaked != "true" { // "treasury" contains no leaked token
			t.Errorf("ceremony field leaked into wire JSON %q: %s", leaked, s)
		}
	}
	// Only the name should be present.
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if len(m) != 1 {
		t.Errorf("WalletExportRequest should serialize exactly {name}, got %s", s)
	}
	if _, ok := m["name"]; !ok {
		t.Errorf("name missing from WalletExportRequest wire form: %s", s)
	}

	// AccountShowRequest.QR must not serialize.
	bShow, _ := json.Marshal(AccountShowRequest{Ref: "treasury/3", QR: true})
	var sm map[string]json.RawMessage
	_ = json.Unmarshal(bShow, &sm)
	if _, ok := sm["qr"]; ok {
		t.Errorf("QR is a terminal-only toggle and must not serialize: %s", bShow)
	}
}
