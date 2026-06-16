package keys

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/daxchain-io/daxie/internal/fsx"
)

// ── the in-memory data model (§3.1) ────────────────────────────────────────────

// Wallet is an HD wallet: one BIP-39 mnemonic, many derived addresses. ID is a
// UUIDv4 assigned at creation and never reused (it is also the secret-blob
// filename stem), so a rename never rewrites a secret file. Name is mutable
// metadata sharing ONE namespace with StandaloneAccount.Name.
type Wallet struct {
	ID         string               // uuid; wallets/<ID>.json
	Name       string               // user-visible
	CreatedAt  time.Time            //
	PathPrefix string               // "m/44'/60'/0'/0" — fixed in v1, stored fwd-compat
	NextIndex  uint32               // monotonic allocator; never decremented, never reused
	Accounts   map[uint32]HDAccount // only *materialized* indexes (derived or aliased)
}

// HDAccount is a materialized HD index: pure metadata, no key file. The private
// key is re-derived from the encrypted mnemonic at signing time (§3.1 decision 1).
type HDAccount struct {
	Index     uint32
	Address   common.Address // cached plaintext (public) — list/show need NO unlock
	Alias     string         // optional; unique within the wallet; never purely numeric
	CreatedAt time.Time
}

// StandaloneAccount is a stock geth v3 key file under accounts/ (§3.1 decision 2).
type StandaloneAccount struct {
	ID        string
	Name      string         // shares the one namespace with wallet names
	Address   common.Address // cached plaintext
	KeyFile   string         // relative: "accounts/UTC--…--<addr>"
	CreatedAt time.Time
}

// AccountInfo is a uniform view over HD + standalone accounts for list/show.
type AccountInfo struct {
	Ref       string         // "treasury/3" / "treasury/payroll" / "ops-key"
	Address   common.Address //
	Kind      string         // "hd" | "standalone"
	Wallet    string         // HD only
	Index     uint32         // HD only
	HasIndex  bool           // distinguishes index 0 from "no index"
	Alias     string         // HD only, optional
	Path      string         // HD only: "m/44'/60'/0'/0/<index>"
	Default   bool           //
	CreatedAt time.Time
}

// Info is the keystore summary (§10.2).
type Info struct {
	Path        string
	Format      int
	Initialized bool
	Wallets     int
	HDAccounts  int
	Accounts    int // standalone count
	KDF         string
	ScryptN     int
}

// ── the on-disk meta.json model ────────────────────────────────────────────────

const metaFormatVersion = 1

// metaFile is the meta.json sidecar (§3.3): names, aliases, HD index map, default
// account. It carries no ciphertext, so it is read/written without touching any
// secret file (different K8s mount perms possible).
type metaFile struct {
	Format         int                        `json:"daxie_meta"`
	DefaultAccount string                     `json:"default_account,omitempty"`
	Wallets        map[string]*metaWallet     `json:"wallets"`  // keyed by wallet UUID
	Accounts       map[string]*metaStandalone `json:"accounts"` // keyed by standalone UUID
}

type metaWallet struct {
	Name       string                    `json:"name"`
	CreatedAt  string                    `json:"created_at"`
	PathPrefix string                    `json:"path_prefix"`
	NextIndex  uint32                    `json:"next_index"`
	Accounts   map[string]*metaHDAccount `json:"accounts"` // keyed by decimal index string
}

type metaHDAccount struct {
	Address   string `json:"address"`
	Alias     string `json:"alias,omitempty"`
	CreatedAt string `json:"created_at"`
}

type metaStandalone struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	File      string `json:"file"`
	CreatedAt string `json:"created_at"`
}

// newMetaFile returns an empty initialized meta model.
func newMetaFile() *metaFile {
	return &metaFile{
		Format:   metaFormatVersion,
		Wallets:  map[string]*metaWallet{},
		Accounts: map[string]*metaStandalone{},
	}
}

// loadMeta reads meta.json under the assumption the caller holds the lock for a
// mutation, or accepts the lock-free read contract (§3.3). A missing meta.json
// returns a fresh empty model (the keystore may have a manifest but no objects
// yet). A perms failure on meta.json is a keystore.perms_insecure tripwire.
func (s *Store) loadMeta() (*metaFile, error) {
	path := s.metaPath()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return newMetaFile(), nil
		}
		return nil, errKeys(CodeStateCorrupt, "cannot stat meta.json: "+err.Error())
	}
	if err := checkPerms(path); err != nil {
		return nil, err
	}
	// Lock-free on POSIX; shared RLock + ERROR_ACCESS_DENIED retry on Windows
	// (§3.3/§7.9) via the platform-split readKeystoreFile.
	b, err := s.readKeystoreFile(path)
	if err != nil {
		return nil, errKeys(CodeStateCorrupt, "cannot read meta.json: "+err.Error())
	}
	var m metaFile
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, errWrap(CodeStateCorrupt, "meta.json is corrupt (not valid JSON)", err)
	}
	if m.Format > metaFormatVersion {
		return nil, errKeysf(CodeStateCorrupt, "meta.json format %d is newer than supported (%d)", m.Format, metaFormatVersion)
	}
	if m.Wallets == nil {
		m.Wallets = map[string]*metaWallet{}
	}
	if m.Accounts == nil {
		m.Accounts = map[string]*metaStandalone{}
	}
	return &m, nil
}

// saveMeta atomically writes meta.json with 0600 perms. The caller MUST hold the
// index.lock. A read-only target maps to keystore.read_only.
func (s *Store) saveMeta(m *metaFile) error {
	m.Format = metaFormatVersion
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return errWrap(CodeStateCorrupt, "cannot encode meta.json", err)
	}
	if err := fsx.WriteAtomic(s.metaPath(), b, 0o600); err != nil {
		if fsx.IsReadOnly(err) {
			return errKeys(CodeKeystoreReadOnly, "the keystore is read-only; meta.json cannot be written (set DAXIE_ACCOUNT to override the default account, or move the keystore to a writable volume)")
		}
		return errWrap(CodeStateCorrupt, "cannot write meta.json", err)
	}
	return nil
}

// ── timestamp helpers (RFC3339, off the wire as a string, §2.5) ────────────────

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ── lookups by name (case-insensitive collision rule, §3.1) ────────────────────

// findWalletByName returns the wallet UUID and entry for a name (case-insensitive
// match, the §3.1 collision rule), or ("", nil) if absent.
func (m *metaFile) findWalletByName(name string) (string, *metaWallet) {
	lc := strings.ToLower(name)
	for id, w := range m.Wallets {
		if strings.ToLower(w.Name) == lc {
			return id, w
		}
	}
	return "", nil
}

// findStandaloneByName returns the standalone UUID and entry for a name
// (case-insensitive), or ("", nil) if absent.
func (m *metaFile) findStandaloneByName(name string) (string, *metaStandalone) {
	lc := strings.ToLower(name)
	for id, a := range m.Accounts {
		if strings.ToLower(a.Name) == lc {
			return id, a
		}
	}
	return "", nil
}

// nameExists reports whether name is already held by ANY keystore object (wallet
// or standalone), the one-namespace check (§3.1). excludeID lets rename skip its
// own entry. Case-insensitive.
func (m *metaFile) nameExists(name, excludeID string) bool {
	lc := strings.ToLower(name)
	for id, w := range m.Wallets {
		if id == excludeID {
			continue
		}
		if strings.ToLower(w.Name) == lc {
			return true
		}
	}
	for id, a := range m.Accounts {
		if id == excludeID {
			continue
		}
		if strings.ToLower(a.Name) == lc {
			return true
		}
	}
	return false
}

// ── name / alias grammar (§3.1) ────────────────────────────────────────────────

// maxNameLen is the §3.1 grammar ceiling: [a-z0-9][a-z0-9_-]{0,63} => 64 chars.
const maxNameLen = 64

// validName enforces the §3.1 name grammar: first char [a-z0-9], rest
// [a-z0-9_-], length 1..64. '/', '#', '.' are reserved (reference separators) and
// rejected by the charset. A name matching the 0x+40-hex address shape is
// rejected (so a name never shadows an address ref). Names are stored
// case-sensitively but collisions are checked case-insensitively (the caller's
// job); validName itself accepts uppercase and lets the caller lowercase-compare.
//
// NOTE: the grammar in the design is lowercase ([a-z0-9]...). We accept exactly
// that — uppercase is rejected — so a name can never collide with a different-case
// name on a case-insensitive filesystem in a way the grammar permits.
func validName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	if looksLikeAddressShape(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isMid := c == '-' || c == '_'
		if i == 0 {
			// First char: lowercase letter or digit only.
			if !isLower && !isDigit {
				return false
			}
			continue
		}
		// Subsequent chars: also '-' / '_'.
		if !isLower && !isDigit && !isMid {
			return false
		}
	}
	return true
}

// validAlias is validName plus the §3.1 rule that an alias must NOT be purely
// numeric (it would collide with an index).
func validAlias(s string) bool {
	if !validName(s) {
		return false
	}
	return !isAllDigits(s)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// looksLikeAddressShape reports the "0x"+40-hex shape (case-insensitive), the
// §3.1 reserved name shape. It does not validate the checksum — any 0x+40hex name
// is reserved.
func looksLikeAddressShape(s string) bool {
	if len(s) != 42 {
		return false
	}
	if s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return false
	}
	for i := 2; i < 42; i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// isHexDigit reports whether c is an ASCII hex digit (either case).
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// ── derivation watermark (§3.3 fail-closed) ────────────────────────────────────

// checkWatermark rejects a meta.json whose next_index is at or below a
// materialized index — the restore-coupling tripwire (§3.3): such a keystore
// would silently reuse a derivation index and mint an address already handed out.
// next_index must be strictly greater than every materialized index.
func (m *metaFile) checkWatermark() error {
	for id, w := range m.Wallets {
		for idxStr := range w.Accounts {
			idx, ok := parseDecimalIndex(idxStr)
			if !ok {
				return errKeysf(CodeStateCorrupt, "wallet %q has a non-numeric account index %q in meta.json", w.Name, idxStr)
			}
			if idx >= w.NextIndex {
				return errKeysf(CodeKeystoreDerivationWatermark,
					"keystore meta.json is inconsistent: wallet %q (%s) has a materialized index %d but next_index is %d; "+
						"this keystore may have been restored without its derivation watermark — refusing to risk reusing a derivation index",
					w.Name, id, idx, w.NextIndex)
			}
		}
	}
	return nil
}

// parseDecimalIndex parses a canonical decimal uint32 index ("0", "3", no leading
// zeros beyond a lone 0). It is the meta.json account-map key parser.
func parseDecimalIndex(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + uint64(s[i]-'0')
		if v > 0xFFFFFFFF {
			return 0, false
		}
	}
	return uint32(v), true
}

func indexKey(i uint32) string { return uitoa(uint64(i)) }

func uitoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// sortedIndexes returns a wallet's materialized indexes in ascending order, for
// deterministic list output.
func sortedIndexes(w *metaWallet) []uint32 {
	out := make([]uint32, 0, len(w.Accounts))
	for k := range w.Accounts {
		if idx, ok := parseDecimalIndex(k); ok {
			out = append(out, idx)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
