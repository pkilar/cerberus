package ebpf

import (
	"fmt"
	"strings"
)

// sliceCgroupPath reconstructs the on-disk cgroupfs path systemd assigns to
// a slice unit name, and computes how many path components deep that is
// relative to cgroupRoot -- the "ancestor level"
// bpf_get_current_ancestor_cgroup_id expects (the cgroup root is level 0,
// each step down the hierarchy is +1; confirmed directly against kernel
// source -- kernel/bpf/helpers.c's bpf_get_current_ancestor_cgroup_id,
// which calls cgroup_ancestor(cgrp, ancestor_level) with level 0 meaning
// the cgroup root).
//
// systemd derives a slice's parent from everything before its LAST "-":
// "cerberus-api.slice" is NOT top-level, it lives at
// ".../cerberus.slice/cerberus-api.slice" (2 levels deep), because
// dash-delimited segments are nested parent slices in systemd's own
// convention. This is computed here, not assumed as a hardcoded constant,
// specifically because this whole feature has been bitten more than once by
// an unverified assumption about kernel/systemd behavior (see
// docs/vsock-connect-detection.md §4.6's history) -- getting this wrong
// would silently point the LSM gate's ancestry check at the wrong cgroup
// level.
func sliceCgroupPath(cgroupRoot, slice string) (path string, level uint32, err error) {
	name, ok := strings.CutSuffix(slice, ".slice")
	if !ok || name == "" {
		return "", 0, fmt.Errorf("vsockwatch/ebpf: %q is not a valid systemd slice unit name (must end in \".slice\" with a non-empty name)", slice)
	}

	segments := strings.Split(name, "-")
	path = cgroupRoot
	for i := range segments {
		path += "/" + strings.Join(segments[:i+1], "-") + ".slice"
	}
	return path, uint32(len(segments)), nil // #nosec G115 -- systemd unit name lengths are bounded, safe conversion
}
