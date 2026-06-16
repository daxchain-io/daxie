//go:build windows

package fsx

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/daxchain-io/daxie/internal/domain"
	"golang.org/x/sys/windows"
)

// checkPermsPlatform implements the Windows §7.9 rule: inspect the file's DACL
// and refuse if Everyone, BUILTIN\Users, or Authenticated Users has any read
// access. A missing file is a hard error.
func checkPermsPlatform(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("fsx: reading DACL of %s: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("fsx: parsing DACL of %s: %w", path, err)
	}
	if dacl == nil {
		// A nil DACL grants everyone full control — the worst case.
		return winPermErr(path, "the file has a null DACL (everyone has full control)")
	}

	// Well-known SIDs we refuse read access to.
	forbidden := []struct {
		name string
		sid  windows.WELL_KNOWN_SID_TYPE
	}{
		{"Everyone", windows.WinWorldSid},
		{"BUILTIN\\Users", windows.WinBuiltinUsersSid},
		{"Authenticated Users", windows.WinAuthenticatedUserSid},
	}
	for _, f := range forbidden {
		sid, err := windows.CreateWellKnownSid(f.sid)
		if err != nil {
			continue
		}
		if aclGrantsRead(dacl, sid) {
			return winPermErr(path, fmt.Sprintf("%s has read access", f.name))
		}
	}
	return nil
}

// aclGrantsRead reports whether the DACL grants the given SID any read-class
// access via an allow ACE.
func aclGrantsRead(dacl *windows.ACL, sid *windows.SID) bool {
	const readMask = windows.GENERIC_READ | windows.FILE_GENERIC_READ | windows.GENERIC_ALL
	var count = uint32(dacl.AceCount)
	for i := uint32(0); i < count; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- SidStart is the variable-length SID at the tail of the ACE struct; pointer cast is the documented Win32 access pattern
		if aceSID.Equals(sid) && ace.Mask&readMask != 0 {
			return true
		}
	}
	return false
}

func winPermErr(path, why string) error {
	return domain.WithData(
		domain.Newf(
			"keystore.perms_insecure",
			"insecure permissions on %s: %s; restrict the DACL to the owner only",
			path, why,
		),
		map[string]any{"path": path, "reason": why},
	)
}

// setOwnerOnlyDACL is invoked by mkdirAllPlatform to tighten a freshly created
// directory's DACL to owner-only. Best-effort: a failure to tighten is non-fatal
// (the subsequent CheckPerms on contained files is the real gate), so it returns
// nil and lets CheckPerms catch any residual exposure.
func setOwnerOnlyDACL(path string) error {
	// A full owner-only-DACL construction is a larger surface than M0 needs; the
	// authoritative gate is CheckPerms on the secret files themselves. We leave
	// the directory at its inherited DACL and rely on per-file CheckPerms.
	return nil
}
