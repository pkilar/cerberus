package ebpf

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestResolveAPISliceCgroup_ResolvesImmediatelyWhenSliceExists(t *testing.T) {
	dir := t.TempDir()
	sliceDir := dir + "/cerberusapi.slice"
	if err := os.Mkdir(sliceDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	cg, level, err := resolveAPISliceCgroup(context.Background(), dir, "cerberusapi.slice")
	if err != nil {
		t.Fatalf("resolveAPISliceCgroup: %v", err)
	}
	if level != 1 {
		t.Errorf("level = %d, want 1", level)
	}
	if cg == 0 {
		t.Error("cg = 0, want a nonzero inode")
	}
}

func TestResolveAPISliceCgroup_RetriesUntilSliceAppears(t *testing.T) {
	restoreAttempts, restoreInterval := apiSliceResolveAttempts, apiSliceResolveInterval
	apiSliceResolveAttempts, apiSliceResolveInterval = 20, 5*time.Millisecond
	defer func() { apiSliceResolveAttempts, apiSliceResolveInterval = restoreAttempts, restoreInterval }()

	dir := t.TempDir()
	sliceDir := dir + "/cerberusapi.slice"

	done := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Millisecond) // simulate the slice appearing shortly after boot ordering
		_ = os.Mkdir(sliceDir, 0o755)
		close(done)
	}()
	defer func() { <-done }()

	cg, _, err := resolveAPISliceCgroup(context.Background(), dir, "cerberusapi.slice")
	if err != nil {
		t.Fatalf("resolveAPISliceCgroup: %v", err)
	}
	if cg == 0 {
		t.Error("cg = 0, want a nonzero inode")
	}
}

func TestResolveAPISliceCgroup_GivesUpIfSliceNeverAppears(t *testing.T) {
	restoreAttempts, restoreInterval := apiSliceResolveAttempts, apiSliceResolveInterval
	apiSliceResolveAttempts, apiSliceResolveInterval = 3, 1*time.Millisecond
	defer func() { apiSliceResolveAttempts, apiSliceResolveInterval = restoreAttempts, restoreInterval }()

	dir := t.TempDir() // slice directory deliberately never created

	if _, _, err := resolveAPISliceCgroup(context.Background(), dir, "cerberusapi.slice"); err == nil {
		t.Fatal("resolveAPISliceCgroup: err = nil, want an error after exhausting retries")
	}
}
