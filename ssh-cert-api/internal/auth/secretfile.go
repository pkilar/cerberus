package auth

import (
	"fmt"
	"os"
)

// CheckSecretFilePerms refuses to proceed if a credential file is readable by
// anyone other than the owner. A world- or group-readable secret hands the
// service's credential to any local user. The role label is interpolated into
// error messages so callers (keytab, LDAP password file, etc.) get a clear
// diagnostic without leaking more of the path than necessary.
func CheckSecretFilePerms(path, role string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat %s %s: %w", role, path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s %s has insecure permissions %#o: must not be group- or world-readable", role, path, mode)
	}
	return nil
}
