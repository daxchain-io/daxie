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

// SetOwnerOnlyDACL is the exported entry the keys provider calls to re-tighten a
// PRE-EXISTING keystore directory's DACL to owner-only (§3.11) — the Windows
// analogue of chmod 0700 on an already-present dir. fsx.MkdirAll already tightens
// dirs it CREATES; this covers a dir created out-of-band. On POSIX this symbol does
// not exist (keys' chmod_unix.go does the chmod instead).
func SetOwnerOnlyDACL(path string) error { return setOwnerOnlyDACL(path) }

// setOwnerOnlyDACL tightens an existing object's DACL to owner-only (§3.11): a
// PROTECTED DACL (inheritance disabled) granting full control to ONLY the process
// owner SID, applied via SetNamedSecurityInfo. PROTECTED is the key bit — it
// detaches the object from a permissive parent DACL so BUILTIN\Users / Everyone do
// not retain inherited read. Used by mkdirAllPlatform on the keystore/state/config
// dirs; freshly created secret FILES get the same DACL at creation time through
// openTemp's SecurityAttributes, so they never transit a permissive state.
func setOwnerOnlyDACL(path string) error {
	sd, err := ownerOnlySD()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("fsx: extracting owner-only DACL: %w", err)
	}
	// DACL_SECURITY_INFORMATION sets the DACL; PROTECTED disables inheritance so the
	// parent's (possibly permissive) ACEs are not merged in.
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("fsx: applying owner-only DACL to %s: %w", path, err)
	}
	return nil
}

// ownerOnlySD builds a self-relative security descriptor granting full control to
// ONLY the current process owner SID, with a PROTECTED + auto-inherited DACL
// (object-inherit + container-inherit so a directory propagates owner-only to new
// children). It reads the owner SID from the current process token. The SD is
// allocated on the Go heap (SecurityDescriptorFromString) and is safe to reference
// from a SecurityAttributes for the duration of a CreateFile call.
func ownerOnlySD() (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := currentOwnerSID()
	if err != nil {
		return nil, err
	}
	// SDDL: Owner = sid; DACL = Protected(P) + Auto-Inherited(AI), one ACE granting
	// Full Access (FA) to the owner, inheritable to objects+containers (OICI).
	//   O:<sid>D:PAI(A;OICI;FA;;;<sid>)
	sddl := "O:" + sid.String() + "D:PAI(A;OICI;FA;;;" + sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("fsx: building owner-only security descriptor: %w", err)
	}
	return sd, nil
}

// currentOwnerSID returns the SID of the current process's token user — the owner
// the owner-only DACL grants access to.
func currentOwnerSID() (*windows.SID, error) {
	tok := windows.GetCurrentProcessToken() // pseudo-token; no Close needed
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("fsx: reading process token user: %w", err)
	}
	return u.User.Sid, nil
}

// ownerOnlySecurityAttributes returns a *SecurityAttributes carrying the
// owner-only security descriptor, for passing to CreateFile so a freshly created
// secret file gets an owner-only DACL at birth (never inheriting a permissive
// parent DACL, §3.11). The returned value (and the SD it points at) must stay
// alive for the duration of the CreateFile call; the caller keeps it on the stack.
func ownerOnlySecurityAttributes() (*windows.SecurityAttributes, error) {
	sd, err := ownerOnlySD()
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}
	sa.Length = uint32(unsafe.Sizeof(*sa)) // #nosec G103 -- Length is the documented Win32 SECURITY_ATTRIBUTES self-size field
	return sa, nil
}
