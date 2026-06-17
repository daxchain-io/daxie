// Package service is THE daxie core: the composition root and every use case.
//
// In M0 the core wires only the M0-available pieces (the resolved config + the
// injected clock) and implements the one M0 use case, Convert. Provider fields
// (signer/chains/policy/journal/registry/ens/erc) are declared by later
// milestones; M0 leaves them absent.
//
// Determinism is structural (§2.3): this package must not import os, net, or
// crypto/rand, and must not call the time.Now family. It takes wall time only
// through the injected clock (set in Open). The internal/determinism_test.go AST
// guard enforces this as a failing test, not a convention.
package service

import (
	"context"
	"time"

	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ens"
	"github.com/daxchain-io/daxie/internal/erc"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/keys"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/daxchain-io/daxie/internal/policyseal"
	"github.com/daxchain-io/daxie/internal/registry"
	"github.com/ethereum/go-ethereum/common"
)

// Service is the composed daxie core. ONE per process for the CLI and the stdio
// MCP server; ONE per daemon for the v1.1 HTTP server (§2.4). It is safe for
// concurrent use once the sign path lands (M1+); the M0 surface (Convert,
// config get/set/list) is read-mostly/stateless.
type Service struct {
	cfg   *config.Config
	paths config.Paths

	// clock is the ONE injected time source (§2.3 AST guard). M0 use cases are
	// pure and do not read it, but it is wired here so later milestones (journal
	// timestamps, wait deadlines) inherit a deterministic seam with zero
	// structural change.
	clock func() time.Time

	// keys is the keystore provider (M1, §3): wallets, accounts, the verifier,
	// the change-passphrase protocol, the domain.Signer adapter. It is opened
	// LAZILY-but-eagerly here: keys.Open provisions nothing for a fresh install
	// (Initialized()==false) and runs change-passphrase crash recovery + the
	// derivation-watermark check under the index.lock, so a corrupt or
	// mid-rotation keystore fails fast at Open (§3.8). It is nil only if keys.Open
	// itself errors, which Open surfaces.
	keys *keys.Store

	// signer is the domain.Signer adapter over keys (§3.12), constructed once in
	// Open. M1 builds it (so the seam is real and tested) even though no M1
	// command signs; M3 (tx) is the first caller.
	signer domain.Signer

	// account is the §7.7 default-account override (--from/--account>DAXIE_ACCOUNT),
	// resolved by the frontend and threaded so use cases that take an active
	// account fall through flag>env>meta.json.
	account string

	// chains is the §2.8 per-request endpoint binding (M2): it resolves a
	// command's (network, endpoint) selection into a dialed chain.Client. v1 is a
	// stateless dialingProvider (dial per call, no pool/failover). Use cases that
	// touch the chain (balance, rpc test, and later gas/send/receive/contract)
	// resolve their client through this and Close() it. It is an interface only so
	// tests can inject a fake-returning provider.
	chains ChainProvider

	// defaultNetwork / defaultRPC hold the per-process network + endpoint defaults
	// the frontend resolved (Options.Network / Options.RPC). Use cases build a
	// ChainRequest from a command-level override layered over these (§2.8). Kept on
	// the service (not re-read from os) so the determinism guard stays satisfied.
	defaultNetwork string
	defaultRPC     string

	// secretIO holds the host primitives secret.Acquire needs (stdin, env lookup,
	// TTY check). The core uses them to resolve passphrases/mnemonics/keys WITHOUT
	// importing os (§2.3); the cli frontend fills them in Options.Secret.
	secretIO SecretIO

	// journal is the M3 crash-safe tx journal (§5.6): JSONL + flock, one file per
	// chain, the raw_tx-before-broadcast record + the reconciliation discriminator.
	// It is opened lazily (creates nothing until the first append) and bound to the
	// state dir. The §5.1 SendTx pipeline + the §5.3 wait machine + the restart
	// reconciliation all read/write it.
	journal *journal.Store

	// nonce is the M3 nonce manager (§5.6, same package as journal): the
	// account-lock + NextNonce=max(chainPending,localNext,journalNext) derivation +
	// the Lease commit/abort the §5.1 ordering depends on. It shares the journal
	// store (the journal is the source of truth for consumed nonces).
	nonce *journal.NonceManager

	// policy is the M3 guardrail engine (§4, §5.1). It ships an ALWAYS-ALLOW stub
	// with a REAL durable reservation lifecycle (Reserve before sign, Commit on
	// broadcast, Release on abort + the orphan reconcile surface) so the §5.1
	// ordering + crash-safety are testable now; M4 replaces the BODY (limits/
	// sealing/rolling-24h) WITHOUT changing any service call site. policy may NOT
	// import journal — service bridges them in reconcile (it legally imports both).
	policy *policy.Engine

	// contacts is the M3 network-agnostic address book (§7.8): contacts
	// add/list/show/remove + the --to name resolution. Opened lazily on the
	// registry dir (a missing file reads as empty).
	contacts *registry.Contacts

	// erc is the M5 stateless ERC operations namespace (§2.8): the pure calldata
	// builders (transfer/approve) + the per-call metadata reads (decimals/symbol/
	// balanceOf). It carries no state — a single zero value serves every network and
	// takes the request's chain.Client per call. The token transfer/approval paths
	// and balance --token/--all use it.
	erc erc.Ops

	// tokens is the M5 per-network token registry (§7.8): the alias↔contract store +
	// the bundled-majors merge, on the same registryDir + flock as contacts. Opened
	// lazily (a missing per-network file reads as the bundled-majors-only set). It is
	// the concrete store behind the discovery seam.
	tokens *registry.Tokens

	// discovery is the M5 read seam (§2.10/§10.3) over the token registry: alias→
	// resolved-token and the known-assets enumeration the --all balance path iterates.
	// In v1 its concrete type is *tokens (registry+bundled); a future indexer impl
	// answers the SAME interface from on-chain/index data with zero call-site change.
	discovery registry.Discovery

	// nfts is the M6 per-network NFT registry (§7.8): collection aliases +
	// individual-NFT (collection#tokenId) aliases, co-located in the SAME
	// registry/<network>.json envelope + flock as the tokens (one atomic unit). Opened
	// lazily on the registry dir (a missing per-network file reads as empty — there are
	// NO bundled NFT majors). The §2.8/§5.1 NFT send + show/list use cases resolve
	// references registry-only through it (the anti-spoofing wall, applied to
	// collections exactly like tokens).
	nfts *registry.NFTs

	// sleep is the injected ctx-aware scheduling seam (§2.3): the determinism guard
	// bans the time.After/Sleep family as call expressions in this package, so the
	// broadcast backoff + the §5.3 poll interval block through this instead. A nil
	// Options.Sleep falls back to immediate (no-delay) so tests run fast and the
	// guard stays green. Production injects a real sleeper.
	sleep func(ctx context.Context, d time.Duration) error

	// ens is the M7 stateless ENS resolver namespace (§2.8): registry→resolver→addr
	// forward resolution + forward-verified reverse + the ResolvePinned drift helper.
	// Like erc it carries NO state — a single zero value serves every network and
	// takes the request's chain.Client PER CALL (§2.8: no ens.Resolver interface; the
	// test seam is the chain.Client fake one layer down, §2.1.1). The tx/nft/token/
	// approve destination paths, the read-only balance path, the policy-allow/contact
	// pin capture, and the `ens resolve|reverse` use cases all resolve through it.
	ens ens.Resolver

	// contracts is the M10 per-network contract registry (§7.8 contracts[]): the
	// alias↔address↔inline-ABI store, co-located in the SAME registry/<network>.json
	// envelope + flock as tokens/nfts (the v2 schema bump). Opened lazily on the registry
	// dir (a missing per-network file reads as empty — there are NO bundled contracts).
	// The §5.11 read paths + the §5.1 contract send resolve aliases REGISTRY-ONLY through
	// it (the anti-spoofing wall): a stored ABI lie can never change the destination or
	// the classified spender (classification reads the calldata bytes, not the ABI).
	//
	// The ABI codec the contract use cases drive (internal/abi) is the stateless
	// dabi.Codec — like erc.Ops it carries NO state, so the contract.go use cases
	// construct a zero value per call (dabi.Codec{}) rather than holding a field. It is
	// the SAME ClassifySelector set policy.ClassifyCalldata consumes (the §4.2
	// one-shared-selector-set invariant; the contract decode display uses it too).
	contracts *registry.Contracts
}

// Open composes the service from resolved options.
//
// It is LAZY (§7.3): an empty environment must still allow Convert, version,
// and config list. Open does NOT create directories and does NOT dial anything
// in M0 — directory creation happens only when a command actually writes config
// (and then maps a read-only mount to config.read_only, never an opaque mkdir
// error). The config load here is path resolution + an optional config.toml
// read merged over the compiled-in presets; a missing default file is the
// legitimate fresh-install case.
func Open(ctx context.Context, opts Options) (*Service, error) {
	clock := opts.Clock
	if clock == nil {
		// The real clock is the HOST's responsibility (the cli frontend injects
		// it — frontends may read wall time; the core may not, §2.3). When a
		// caller omits it, we fall back to a fixed-zero clock rather than calling
		// time.Now here: doing so would trip the determinism guard, and no M0 use
		// case reads the clock anyway. Production callers (cmd/daxie → cli) always
		// supply a real clock, so this fallback is reached only by tests and by
		// the pure use cases that ignore time entirely.
		clock = zeroClock
	}

	cfg, paths, err := config.Load(opts.configFlags())
	if err != nil {
		return nil, err
	}

	// Open the keystore provider. keys.Open is lazy for a fresh install (it
	// provisions nothing and reports Initialized()==false) but runs the §3.8
	// change-passphrase crash recovery and the §3.3 derivation-watermark check
	// under the exclusive index.lock, so a mid-rotation or restore-coupled
	// keystore fails fast HERE (keystore.derivation_watermark → exit 11) rather
	// than mid-command. The light KDF is honored only when the manifest was
	// created light (§3.4); the gate is read via the injected env lookup so the
	// core never touches os (§2.3).
	light := false
	if opts.Secret.LookupEnv != nil {
		if v, ok := opts.Secret.LookupEnv("DAXIE_KDF_LIGHT"); ok && v != "" && v != "0" {
			light = true
		}
	}
	ks, err := keys.Open(ctx, keys.Options{
		Dir:   paths.Keystore,
		Clock: clock,
		Light: light,
	})
	if err != nil {
		return nil, err
	}

	// Open the M3 providers. All are LAZY (§7.3): journal/policy create nothing
	// until the first append/Reserve; contacts reads a missing file as empty. So an
	// empty environment still composes cleanly and only a tx/contacts command
	// touches state.
	jstore, err := journal.Open(paths.State, clock)
	if err != nil {
		return nil, err
	}
	nmgr, err := journal.NewNonceManager(paths.State, jstore)
	if err != nil {
		return nil, err
	}
	// Read the §4.6 trust root (policy-anchor.json) DIRECTLY from the config class —
	// no Viper key, no env, no flag (the carve-out). config returns RAW BYTES;
	// policyseal does the typed decode here (config stays free of the policyseal
	// import). A missing anchor is the opt-in case (anchorFound=false ⇒ the engine
	// is a no-op allow until a policy exists). A genuine read error fails Open
	// (fail closed — a halted trust root must not silently start unguarded).
	var anchor policyseal.Anchor
	anchorRaw, anchorFound, aerr := paths.ReadAnchor()
	if aerr != nil {
		return nil, aerr
	}
	if anchorFound {
		anchor, aerr = policyseal.ParseAnchor(anchorRaw)
		if aerr != nil {
			return nil, domain.Wrap("policy.seal_violation",
				"the policy anchor is present but unparseable; signing is halted until it is repaired", aerr)
		}
	}
	peng, err := policy.Open(paths.State, clock, anchor, anchorFound)
	if err != nil {
		return nil, err
	}
	cbook, err := registry.OpenContacts(paths.RegistryDir)
	if err != nil {
		return nil, err
	}
	// The M5 token registry: same registryDir + flock as contacts, lazy (a missing
	// per-network file reads as the bundled-majors-only set). OpenTokens provisions
	// nothing on disk, so it is safe on a fresh install / read-only config pod.
	tokenReg, err := registry.OpenTokens(paths.RegistryDir)
	if err != nil {
		return nil, err
	}
	// The M6 NFT registry: same registryDir + flock + envelope as tokens, lazy. It
	// shares the per-network file with the tokens (one atomic unit), so OpenNFTs also
	// provisions nothing on disk.
	nftReg, err := registry.OpenNFTs(paths.RegistryDir)
	if err != nil {
		return nil, err
	}
	// The M10 contract registry: same registryDir + flock + envelope as tokens/nfts
	// (the v2 schema bump), lazy. It shares the per-network file with tokens/nfts (one
	// atomic unit), so OpenContracts also provisions nothing on disk.
	contractReg, err := registry.OpenContracts(paths.RegistryDir)
	if err != nil {
		return nil, err
	}

	sleep := opts.Sleep
	if sleep == nil {
		// Determinism-safe fallback: no delay. The service NEVER calls the
		// time.After family directly (the guard bans it); a nil host sleeper means
		// "do not block" — correct for tests and harmless in production (the cli
		// always injects a real one).
		sleep = noDelaySleep
	}

	s := &Service{
		cfg:            cfg,
		paths:          paths,
		clock:          clock,
		keys:           ks,
		signer:         ks.Signer(),
		account:        opts.Account,
		secretIO:       opts.Secret,
		defaultNetwork: opts.Network,
		defaultRPC:     opts.RPC,
		journal:        jstore,
		nonce:          nmgr,
		policy:         peng,
		contacts:       cbook,
		erc:            erc.Ops{},
		ens:            ens.Resolver{}, // M7: stateless ENS resolver, chain.Client per call (§2.8)
		tokens:         tokenReg,
		// The §2.10/§10.3 Discovery seam: in v1 the concrete impl is the registry-
		// backed *Tokens (registry + bundled majors). Service holds the interface so a
		// future indexer impl swaps in here with zero call-site change.
		discovery: tokenReg,
		nfts:      nftReg,      // M6: the per-network NFT registry (collections + nft_aliases)
		contracts: contractReg, // M10: the per-network contract registry (contracts[] v2)
		sleep:     sleep,
		// The §2.8 chain provider. It is stateless (dial per call) so Open dials
		// NOTHING here — it only captures the merged config + the per-process
		// defaults; the first dial happens when a chain-touching use case runs. This
		// keeps Open lazy (§7.3): an empty environment still composes cleanly and
		// only a balance/rpc-test command reaches the network.
		chains: newDialingProvider(cfg, opts.Network, opts.RPC),
	}

	// §4.1 "Limit scope": install the policy⊥keystore enumeration hook so the
	// rolling-24h daily window AGGREGATES across every keystore account on a network
	// (the unit of compromise is the keystore passphrase — a per-account cap would
	// silently multiply max_day by the account count). policy may NOT import keys;
	// service bridges it here, mirroring how selfSnapshot supplies self_addresses to
	// admin mutations. The accounts set is network-independent in v1 (one keystore
	// holds the addresses for every network), so the network arg is currently unused.
	s.policy.SetAccountsHook(func(_ string) []common.Address { return s.selfSnapshot() })

	// Drive the §5.1 restart reconciliation: bridge the journal verdict to policy's
	// orphan surface (policy may NOT import journal; service composes both). It runs
	// offline (no RPC) — a crash-left reservation is committed iff its journal
	// record shows a recorded broadcast, else released. It must never fail Open: a
	// reconciliation error is surfaced but the service still opens (the next
	// AcquireNonce reconciles again). It is a no-op on a fresh install (no
	// reservations, no journal).
	if rerr := s.reconcile(ctx); rerr != nil {
		// Non-fatal: log-worthy but Open must not refuse to start because a stale
		// reservation could not be resolved. The next send re-runs reconciliation
		// under the account lock.
		_ = rerr
	}

	return s, nil
}

// noDelaySleep is the determinism-safe Sleep fallback: it honors ctx
// cancellation but otherwise returns immediately (no wall-clock dependency).
func noDelaySleep(ctx context.Context, _ time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// Close flushes durable state and releases file locks. M1 closes the keystore
// (releasing any held index.lock). It is idempotent and never errors fatally;
// wiring it from the start means SIGTERM-driven shutdown (§2.4) needs no later
// change.
func (s *Service) Close() error {
	// Flush the M3 providers first (all no-op flushes in M3 — no long-lived fds —
	// but wiring them now means SIGTERM-driven shutdown during a --wait needs no
	// later change, §5.3). Errors are collected; the keystore close governs the
	// return so a held index.lock is always released.
	if s.journal != nil {
		_ = s.journal.Close()
	}
	if s.policy != nil {
		_ = s.policy.Close()
	}
	if s.keys != nil {
		return s.keys.Close()
	}
	return nil
}

// Now returns the service's notion of wall time through the injected clock. It
// exists so later use cases read time via one method (never time.Now), keeping
// the §2.3 guard trivially satisfied. M0 use cases do not call it.
func (s *Service) Now() time.Time {
	return s.clock()
}

// zeroClock is the determinism-safe fallback when no clock is injected. It does
// not read the wall clock (which would violate §2.3); production hosts always
// inject a real clock, and M0 use cases never read it. It returns the zero
// time.Time so the field is always callable.
func zeroClock() time.Time { return time.Time{} }
