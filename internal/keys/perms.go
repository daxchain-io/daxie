package keys

import (
	"errors"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
)

// checkPerms enforces the §7.9 permission rule on a secret/metadata file and maps
// any failure to the canonical keystore.perms_insecure code (exit 12) — a
// misconfig tripwire, not a daxie bug (§3.11). fsx.CheckPerms already returns a
// typed *domain.Error; we re-stamp it with keystore.perms_insecure so the
// keystore surface is consistent regardless of fsx's internal code choice.
//
// On Windows fsx inspects the DACL (refuses Everyone / BUILTIN\Users /
// Authenticated Users read); on POSIX it rejects any world bit or group-write and
// warns on a foreign-group read. keys does not duplicate any of that — it calls
// fsx and re-codes the result.
func checkPerms(path string) error {
	err := fsx.CheckPerms(path)
	if err == nil {
		return nil
	}
	// Preserve the original message/cause but ensure the code is the keystore one.
	var de *domain.Error
	if errors.As(err, &de) {
		return errWrap(CodeKeystorePermsInsecure, de.Msg, err)
	}
	return errWrap(CodeKeystorePermsInsecure, "insecure permissions on "+path, err)
}
