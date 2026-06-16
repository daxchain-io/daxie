package fsx

import (
	"io"
	"os"
)

// skipPermCheckEnv disables CheckPerms for filesystems that cannot represent
// POSIX modes (some CSI / network mounts). It is NEVER the documented answer for
// the fsGroup case (§7.9).
const skipPermCheckEnv = "DAXIE_SKIP_PERM_CHECK"

// permWarnSink receives the non-fatal group-read-by-foreign-group warning. It is
// a package variable so the cli frontend can route it to stderr and tests can
// capture it. Defaults to os.Stderr.
var permWarnSink io.Writer = os.Stderr

// lookupEnvFn is os.LookupEnv, swappable in tests so DAXIE_SKIP_PERM_CHECK can be
// exercised without mutating the real process environment.
var lookupEnvFn = os.LookupEnv

// CheckPerms enforces the §7.9 permission rule on a secret/integrity-bearing
// file:
//
//   - hard error (returns *domain.Error) if mode&0o037 != 0 — any world bit or
//     group-write;
//   - group-read (0o040) is accepted SILENTLY iff the file's group is the
//     process's effective GID or a supplementary group (the blessed K8s fsGroup
//     shape: a 0440 Secret), else a one-line WARNING is emitted but the check
//     passes;
//   - on Windows the DACL is inspected (refuses Everyone / BUILTIN\Users /
//     Authenticated Users read).
//
// DAXIE_SKIP_PERM_CHECK=1 disables the check entirely. A missing file is a hard
// error (the caller expected it to exist).
func CheckPerms(path string) error {
	if v, ok := lookupEnvFn(skipPermCheckEnv); ok && v == "1" {
		return nil
	}
	return checkPermsPlatform(path)
}
