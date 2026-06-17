package config

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
)

// anchor.go is the config-class trust-root I/O for the §4.6 policy anchor
// (policy-anchor.json). The anchor pins the seal verify key + scrypt salt/params +
// the monotonic nonce watermark. It is read and written DIRECTLY by config —
// deliberately OUTSIDE Viper:
//
//   - it is NOT in config.toml and is NEVER a Viper key;
//   - no flag and no DAXIE_* env var can set it (`config get|set` already reject
//     the policy.* subtree, getset.go);
//   - so a compromised agent cannot outvote the admin passphrase by pairing a
//     self-forged policy.json with a verify key it set from its own environment
//     (requirements §5: "Viper's flags > env precedence would otherwise let a
//     compromised agent outvote the admin passphrase from its own process
//     environment").
//
// config returns and accepts RAW BYTES; the typed decode lives in
// internal/policyseal (policyseal.ParseAnchor). This keeps config free of the
// policyseal import (no config→policyseal edge in the arch matrix): the anchor
// JSON flows config → service → policy → policyseal as opaque bytes on read, and
// the reverse on write.

// anchorFileName is the canonical anchor basename in the config class (§4.6).
const anchorFileName = "policy-anchor.json"

// anchorMode is the anchor file permission. It carries no secret (only a PUBLIC
// verify key + a public salt + a counter), but it is owner-only by default for
// the same §7.9 posture as config.toml.
const anchorMode os.FileMode = 0o600

// anchorLockTimeout bounds anchor lock acquisition (the policy-anchor.lock
// sidecar). A timeout maps to state.lock_timeout (exit 11) — contention.
const anchorLockTimeout = 30 * time.Second

// AnchorPath returns <ConfigDir>/policy-anchor.json — the anchor lives beside the
// config file (config class) so the one K8s mount the agent process genuinely
// cannot write (a read-only ConfigMap) protects it (§4.6).
func (p Paths) AnchorPath() string {
	return filepath.Join(p.ConfigDir, anchorFileName)
}

// ReadAnchor reads the raw anchor bytes from the config class. It takes a SHARED
// lock on the policy-anchor.lock sidecar (a Daxie-internal consistency measure, so
// a concurrent `policy set` write never tears the read). It returns:
//
//   - (bytes, true, nil)  when an anchor exists and was read;
//   - (nil, false, nil)   when no anchor exists yet (the opt-in / pre-bootstrap
//     case — the engine treats "no anchor AND no policy" as a no-op allow, §4);
//   - (nil, false, err)   on a genuine read/lock failure (fail closed).
//
// A missing anchor is NOT an error: a fresh install has none, and the engine's
// opt-in rule needs the (found=false) signal, not an error. The typed decode +
// the "anchor present ⇒ a missing policy is itself a violation" rule live above
// this read (policyseal.ParseAnchor + policy.loadPolicy).
func (p Paths) ReadAnchor() (raw []byte, found bool, err error) {
	path := p.AnchorPath()

	// Shared lock for a consistent read. The lock dir is the config dir, which may
	// not exist yet on a fresh install — that is exactly the not-found case, so a
	// missing dir is reported as "no anchor", never an error.
	if _, statErr := os.Stat(path); statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, false, nil
		}
		return nil, false, domain.Wrap(domain.CodeConfigInvalid,
			"cannot stat the policy anchor "+path+": "+statErr.Error(), statErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), anchorLockTimeout)
	defer cancel()
	unlock, lerr := fsx.RLock(ctx, path)
	if lerr != nil {
		return nil, false, mapLockErr(path, lerr)
	}
	defer unlock()

	b, rerr := os.ReadFile(path) // #nosec G304 -- fixed anchor path under the config dir
	if rerr != nil {
		if os.IsNotExist(rerr) {
			// Raced with a delete between Stat and ReadFile; treat as not-found.
			return nil, false, nil
		}
		return nil, false, domain.Wrap(domain.CodeConfigInvalid,
			"cannot read the policy anchor "+path+": "+rerr.Error(), rerr)
	}
	return b, true, nil
}

// WriteAnchor writes the raw anchor bytes to the config class atomically under the
// policy-anchor.lock sidecar (fsx.WriteAtomic, §7.9). It is the §4.6 direct anchor
// writer that `daxie policy set` / `change-admin-passphrase` call (via service)
// when the config class is WRITABLE (a workstation).
//
// A read-only mount (the K8s ConfigMap) maps to config.read_only (exit 10) — the
// caller branches on that to fall back to emitting the anchor JSON to stdout /
// --anchor-out for the operator to land into the ConfigMap out-of-band (§4.6). The
// anchor bytes are produced by the caller (policyseal's canonical Marshal); config
// only persists them.
//
// K8s TWO-DOMAIN WRITE ORDERING (§4.7): the policy file (state PVC) is written
// FIRST, then the anchor (config ConfigMap). A failure between the two leaves
// file.nonce > anchor.watermark, which the runtime ACCEPTS (it self-heals the
// watermark forward when writable); anchor-first would self-inflict a
// policy.rollback halt. This ordering is the caller's (service) responsibility —
// WriteAnchor is the second write; service must have already written policy.json.
func (p Paths) WriteAnchor(raw []byte) error {
	path := p.AnchorPath()

	// Lazily create the config dir (mirrors SetKey). A read-only parent surfaces as
	// config.read_only via the mapping below.
	if err := fsx.MkdirAll(p.ConfigDir, 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return readOnlyErr(path, err)
		}
		return domain.Wrap(domain.CodeConfigInvalid,
			"creating config dir "+p.ConfigDir+": "+err.Error(), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), anchorLockTimeout)
	defer cancel()
	unlock, lerr := fsx.Lock(ctx, path)
	if lerr != nil {
		return mapLockErr(path, lerr)
	}
	defer unlock()

	if err := fsx.WriteAtomic(path, raw, anchorMode); err != nil {
		if fsx.IsReadOnly(err) {
			return readOnlyErr(path, err)
		}
		return domain.Wrap(domain.CodeConfigInvalid,
			"writing the policy anchor "+path+": "+err.Error(), err)
	}
	return nil
}

// AnchorIsReadOnly reports whether a WriteAnchor failure is the read-only-mount
// case (config.read_only). The caller (service) uses it to choose the §4.6
// fallback: emit the anchor JSON to stdout / --anchor-out instead of failing the
// whole `policy set` (the K8s ConfigMap path). It is a thin re-export of the
// domain code check so the cli/service do not string-match.
func AnchorIsReadOnly(err error) bool {
	if err == nil {
		return false
	}
	return domain.AsError(err).Code == domain.CodeConfigReadOnly
}
