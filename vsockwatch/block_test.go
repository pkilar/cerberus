package vsockwatch

import (
	"context"
	"errors"
	"math"
	"syscall"
	"testing"
)

func TestProcessKiller_Block_SendsSIGKILL(t *testing.T) {
	orig := killProcess
	defer func() { killProcess = orig }()

	var gotPID int
	var gotSig syscall.Signal
	killProcess = func(pid int, sig syscall.Signal) error {
		gotPID, gotSig = pid, sig
		return nil
	}

	k := ProcessKiller{}
	if err := k.Block(context.Background(), Event{PID: 4242}); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if gotPID != 4242 {
		t.Errorf("killProcess called with pid=%d, want 4242", gotPID)
	}
	if gotSig != syscall.SIGKILL {
		t.Errorf("killProcess called with signal=%v, want SIGKILL", gotSig)
	}
}

func TestProcessKiller_Block_NoPID(t *testing.T) {
	orig := killProcess
	defer func() { killProcess = orig }()

	called := false
	killProcess = func(int, syscall.Signal) error {
		called = true
		return nil
	}

	k := ProcessKiller{}
	if err := k.Block(context.Background(), Event{PID: 0}); err == nil {
		t.Fatal("expected an error for a zero pid")
	}
	if called {
		t.Error("killProcess must not be called when the event has no pid")
	}
}

func TestProcessKiller_Block_RejectsOversizedPID(t *testing.T) {
	orig := killProcess
	defer func() { killProcess = orig }()

	called := false
	killProcess = func(int, syscall.Signal) error {
		called = true
		return nil
	}

	k := ProcessKiller{}
	// math.MaxInt32+1: on a 32-bit int build this would wrap to a negative
	// value, which POSIX kill(2) reinterprets as "signal this process
	// GROUP" instead of a single process — must be refused, not converted.
	if err := k.Block(context.Background(), Event{PID: math.MaxInt32 + 1}); err == nil {
		t.Fatal("expected an error for a pid beyond maxKillablePID")
	}
	if called {
		t.Error("killProcess must not be called for an out-of-range pid")
	}
}

func TestProcessKiller_Block_PropagatesError(t *testing.T) {
	orig := killProcess
	defer func() { killProcess = orig }()

	killProcess = func(int, syscall.Signal) error {
		return errors.New("operation not permitted")
	}

	k := ProcessKiller{}
	if err := k.Block(context.Background(), Event{PID: 1}); err == nil {
		t.Fatal("expected killProcess's error to propagate")
	}
}
