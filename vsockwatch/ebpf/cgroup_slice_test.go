package ebpf

import "testing"

func TestSliceCgroupPath(t *testing.T) {
	tests := []struct {
		name      string
		slice     string
		wantPath  string
		wantLevel uint32
		wantErr   bool
	}{
		{
			name:      "dash-nested slice",
			slice:     "cerberus-api.slice",
			wantPath:  "/sys/fs/cgroup/cerberus.slice/cerberus-api.slice",
			wantLevel: 2,
		},
		{
			name:      "top-level slice (no dash)",
			slice:     "cerberusapi.slice",
			wantPath:  "/sys/fs/cgroup/cerberusapi.slice",
			wantLevel: 1,
		},
		{
			name:      "three-segment nesting",
			slice:     "cerberus-api-preventive.slice",
			wantPath:  "/sys/fs/cgroup/cerberus.slice/cerberus-api.slice/cerberus-api-preventive.slice",
			wantLevel: 3,
		},
		{
			name:    "wrong suffix",
			slice:   "cerberus-api.service",
			wantErr: true,
		},
		{
			name:    "empty name before .slice",
			slice:   ".slice",
			wantErr: true,
		},
		{
			name:    "empty string",
			slice:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, level, err := sliceCgroupPath("/sys/fs/cgroup", tt.slice)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
			if level != tt.wantLevel {
				t.Errorf("level = %d, want %d", level, tt.wantLevel)
			}
		})
	}
}
