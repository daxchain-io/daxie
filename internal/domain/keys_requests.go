package domain

// This file is the wire contract for the M1 wallet/account/keystore use cases
// (§2.5, §3.1–§3.3, cli-spec §1). Every type obeys the triple-duty rule:
//
//   - NO float field anywhere (§2.5): indices are uint32, counts are int, all
//     user-facing scalars that could exceed an int64 or carry units are strings.
//   - Every user value is a string on the wire (addresses, mnemonics, keys,
//     timestamps as RFC3339 strings — never a time.Time).
//   - json + jsonschema struct tags so the same struct serves the CLI --json
//     output, the MCP tool schema (M11), and the v1.1 HTTP body.
//
// SECRET MATERIAL NEVER APPEARS IN A *REQUEST* STRUCT. Passphrases, mnemonics,
// BIP-39 passphrases and raw private keys are resolved by the frontend via the
// §3.6 acquisition precedence (internal/secret) and handed to the service method
// as *secret.Bytes OUT OF BAND — a non-JSON method parameter. They therefore
// never serialize, never reach a journal/log, and the MCP schema omits them for
// free (consistent with §6.1: there are NO wallet/account create/import/export
// MCP tools). Result structs DO carry freshly-revealed sensitive values
// (mnemonic on create/export, private key on account export); those are flagged
// with Sensitive and shown once, never persisted.
//
// CLI-only, non-serialized fields (json:"-"): the non-interactive confirm gate
// (Yes), the typed-name confirmation ceremony (Confirm), and the terminal-only QR
// toggle (QR). They are excluded from the MCP schema by the json:"-" tag because
// they are frontend ceremony, not core inputs.
//
// Principal and (where progress is emitted) EventSink are threaded by the SERVICE
// method signature — (ctx, Principal, Request, EventSink) → (Result, error) — not
// stored in these structs.

// ─── wallet ────────────────────────────────────────────────────────────────────

// WalletCreateRequest creates a new HD wallet and auto-derives account 0.
type WalletCreateRequest struct {
	Name  string `json:"name" jsonschema:"wallet name; grammar [a-z0-9][a-z0-9_-]{0,63}, reserved chars / # . forbidden"`
	Words int    `json:"words,omitempty" jsonschema:"type=integer,enum=12,enum=24; mnemonic length, default 12"`
	Yes   bool   `json:"-"` // CLI-only non-interactive confirm gate; excluded from the MCP schema.
}

// WalletCreateResult reports the new wallet plus the once-shown mnemonic.
type WalletCreateResult struct {
	Name             string `json:"name"`
	WalletID         string `json:"wallet_id"`          // keystore UUID
	PathPrefix       string `json:"path_prefix"`        // "m/44'/60'/0'/0"
	Account0         string `json:"account0"`           // "<name>/0", the auto-derived account ref
	Account0Address  string `json:"account0_address"`   // EIP-55 hex
	Mnemonic         string `json:"mnemonic,omitempty"` // SENSITIVE: shown ONCE on create
	BIP39Passphrase  string `json:"bip39_passphrase,omitempty"`
	Sensitive        bool   `json:"sensitive,omitempty"`              // true when Mnemonic is present
	PassphraseFinger string `json:"passphrase_fingerprint,omitempty"` // salted non-secret hash, first-init only
}

// WalletImportRequest imports an existing BIP-39 mnemonic as a wallet. The
// mnemonic and optional BIP-39 passphrase arrive as *secret.Bytes out of band.
type WalletImportRequest struct {
	Name string `json:"name" jsonschema:"wallet name; grammar [a-z0-9][a-z0-9_-]{0,63}"`
	Yes  bool   `json:"-"`
}

// WalletImportResult mirrors create minus the once-shown mnemonic (the operator
// already holds it).
type WalletImportResult struct {
	Name            string `json:"name"`
	WalletID        string `json:"wallet_id"`
	PathPrefix      string `json:"path_prefix"`
	Account0        string `json:"account0"`
	Account0Address string `json:"account0_address"`
}

// WalletListRequest lists every wallet (no filter in v1).
type WalletListRequest struct{}

// WalletListResult is the wallet roster.
type WalletListResult struct {
	Wallets []WalletSummary `json:"wallets"`
}

// WalletSummary is one wallet row.
type WalletSummary struct {
	Name      string `json:"name"`
	WalletID  string `json:"wallet_id"`
	Accounts  int    `json:"accounts"`   // materialized HD accounts
	CreatedAt string `json:"created_at"` // RFC3339 string, never a time.Time on the wire
}

// WalletShowRequest shows one wallet by name.
type WalletShowRequest struct {
	Name string `json:"name"`
}

// WalletShowResult details a wallet and its derived accounts.
type WalletShowResult struct {
	Name       string           `json:"name"`
	WalletID   string           `json:"wallet_id"`
	PathPrefix string           `json:"path_prefix"`
	NextIndex  uint32           `json:"next_index"`
	CreatedAt  string           `json:"created_at"`
	Accounts   []AccountSummary `json:"accounts"`
}

// WalletRenameRequest renames a wallet within the shared namespace.
type WalletRenameRequest struct {
	Old string `json:"old" jsonschema:"current wallet name"`
	New string `json:"new" jsonschema:"new wallet name; grammar [a-z0-9][a-z0-9_-]{0,63}"`
}

// WalletRenameResult confirms the rename.
type WalletRenameResult struct {
	Old      string `json:"old"`
	New      string `json:"new"`
	WalletID string `json:"wallet_id"`
}

// WalletExportRequest exports a wallet's mnemonic (freshly authed, §3.9). The
// passphrase arrives as *secret.Bytes out of band.
type WalletExportRequest struct {
	Name    string `json:"name"`
	Yes     bool   `json:"-"` // non-TTY confirm gate (§3.9)
	Confirm string `json:"-"` // typed-name confirmation (TTY ceremony), CLI-only
}

// WalletExportResult carries the recovered mnemonic. Always sensitive.
type WalletExportResult struct {
	Name            string `json:"name"`
	Mnemonic        string `json:"mnemonic"`
	BIP39Passphrase string `json:"bip39_passphrase,omitempty"`
	Sensitive       bool   `json:"sensitive"` // always true
}

// WalletDeleteRequest deletes a wallet (blob + meta entry).
type WalletDeleteRequest struct {
	Name    string `json:"name"`
	Yes     bool   `json:"-"`
	Confirm string `json:"-"`
}

// WalletDeleteResult confirms the deletion.
type WalletDeleteResult struct {
	Name     string `json:"name"`
	WalletID string `json:"wallet_id"`
	Deleted  bool   `json:"deleted"`
}

// ─── account ───────────────────────────────────────────────────────────────────

// AccountSummary is one account row, HD or standalone (shared namespace).
type AccountSummary struct {
	Ref       string  `json:"ref"`               // "treasury/3" or "ops-key"
	Address   string  `json:"address"`           // EIP-55 hex
	Kind      string  `json:"kind"`              // "hd" | "standalone"
	Wallet    string  `json:"wallet,omitempty"`  // HD only
	Index     *uint32 `json:"index,omitempty"`   // HD only; pointer so 0 is distinguishable from absent
	Alias     string  `json:"alias,omitempty"`   // HD only, when set
	Default   bool    `json:"default,omitempty"` // the `account use` default
	CreatedAt string  `json:"created_at"`
}

// AccountDeriveRequest derives an HD account. Index nil derives the next free
// index; an explicit Index re-derives (idempotent) a specific one.
type AccountDeriveRequest struct {
	Wallet string  `json:"wallet" jsonschema:"the HD wallet name to derive from"`
	Index  *uint32 `json:"index,omitempty" jsonschema:"type=integer,minimum=0; omit to derive next"`
	Name   string  `json:"name,omitempty" jsonschema:"optional alias to set in one step; not purely numeric"`
	Yes    bool    `json:"-"`
}

// AccountDeriveResult reports the derived account.
type AccountDeriveResult struct {
	Ref     string `json:"ref"` // "<wallet>/<index>"
	Address string `json:"address"`
	Index   uint32 `json:"index"`
	Alias   string `json:"alias,omitempty"`
}

// AccountAliasRequest sets an alias on an existing HD account. Ref is the
// numeric-index form ("treasury/3").
type AccountAliasRequest struct {
	Ref   string `json:"ref" jsonschema:"the HD account ref to alias, index form e.g. treasury/3"`
	Alias string `json:"alias" jsonschema:"grammar [a-z0-9][a-z0-9_-]{0,63}; must NOT be purely numeric"`
}

// AccountAliasResult confirms the alias.
type AccountAliasResult struct {
	Ref     string `json:"ref"`
	Alias   string `json:"alias"`
	Address string `json:"address"`
}

// AccountUnaliasRequest removes an alias. Ref may be the alias form
// ("treasury/payroll") or the index form.
type AccountUnaliasRequest struct {
	Ref string `json:"ref"`
}

// AccountUnaliasResult reports the cleared alias.
type AccountUnaliasResult struct {
	Wallet       string `json:"wallet"`
	Index        uint32 `json:"index"`
	RemovedAlias string `json:"removed_alias"`
}

// AccountImportRequest imports a standalone raw private key under a name. The raw
// key arrives as *secret.Bytes out of band.
type AccountImportRequest struct {
	Name string `json:"name" jsonschema:"standalone account name; grammar [a-z0-9][a-z0-9_-]{0,63}"`
	Yes  bool   `json:"-"`
}

// AccountImportResult reports the imported account.
type AccountImportResult struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	AccountID string `json:"account_id"`
}

// AccountUseRequest sets the default signing account (`account use`).
type AccountUseRequest struct {
	Ref string `json:"ref"`
}

// AccountUseResult confirms the new default.
type AccountUseResult struct {
	Ref     string `json:"ref"`
	Address string `json:"address"`
}

// AccountListRequest lists accounts, optionally filtered to one wallet.
type AccountListRequest struct {
	Wallet string `json:"wallet,omitempty"` // empty = all wallets + standalone
}

// AccountListResult is the account roster plus the current default ref.
type AccountListResult struct {
	Accounts []AccountSummary `json:"accounts"`
	Default  string           `json:"default,omitempty"`
}

// AccountShowRequest shows one account. QR is a terminal-only render toggle.
type AccountShowRequest struct {
	Ref string `json:"ref"`
	QR  bool   `json:"-"` // CLI render-only; never on the wire / MCP schema
}

// AccountShowResult details one account.
type AccountShowResult struct {
	Ref     string  `json:"ref"`
	Address string  `json:"address"`
	Kind    string  `json:"kind"` // "hd" | "standalone"
	Wallet  string  `json:"wallet,omitempty"`
	Index   *uint32 `json:"index,omitempty"`
	Alias   string  `json:"alias,omitempty"`
	Path    string  `json:"path,omitempty"` // full BIP-44 path for HD, e.g. "m/44'/60'/0'/0/3"
	Default bool    `json:"default,omitempty"`
}

// AccountExportRequest exports a STANDALONE account's private key (freshly authed,
// §3.9). HD accounts are not individually exportable here — use wallet export.
// The passphrase arrives as *secret.Bytes out of band.
type AccountExportRequest struct {
	Ref     string `json:"ref"`
	Yes     bool   `json:"-"`
	Confirm string `json:"-"`
}

// AccountExportResult carries the revealed private key. Always sensitive.
type AccountExportResult struct {
	Ref        string `json:"ref"`
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"` // 0x-hex, SENSITIVE
	Sensitive  bool   `json:"sensitive"`   // always true
}

// AccountDeleteRequest deletes an account. HD accounts are forgotten (mnemonic
// still holds them); standalone accounts are removed (key file deleted).
type AccountDeleteRequest struct {
	Ref     string `json:"ref"`
	Yes     bool   `json:"-"`
	Confirm string `json:"-"`
}

// AccountDeleteResult reports the deletion mode.
type AccountDeleteResult struct {
	Ref     string `json:"ref"`
	Mode    string `json:"mode"` // "forget" (HD) | "remove" (standalone)
	Deleted bool   `json:"deleted"`
}

// ─── keystore ──────────────────────────────────────────────────────────────────

// KeystoreInfoRequest reports keystore status (no inputs).
type KeystoreInfoRequest struct{}

// KeystoreInfoResult summarizes the keystore (§10.2). No float: scrypt N is an int
// (a power of two well within int range).
type KeystoreInfoResult struct {
	Path        string `json:"path"`
	Format      int    `json:"format"` // daxie_keystore manifest version
	Wallets     int    `json:"wallets"`
	Accounts    int    `json:"accounts"`    // standalone account count
	HDAccounts  int    `json:"hd_accounts"` // materialized HD account count
	Initialized bool   `json:"initialized"` // verifier present?
	KDF         string `json:"kdf"`         // "scrypt"
	ScryptN     int    `json:"scrypt_n"`    // template default cost (2^18 standard, 2^12 light)
}

// KeystoreChangePassphraseRequest rotates the keystore passphrase. Old and new
// passphrases arrive as *secret.Bytes out of band.
type KeystoreChangePassphraseRequest struct {
	Yes bool `json:"-"`
}

// KeystoreChangePassphraseResult reports the rotation outcome.
type KeystoreChangePassphraseResult struct {
	RotatedFiles     int    `json:"rotated_files"`
	PassphraseFinger string `json:"passphrase_fingerprint"`
}
