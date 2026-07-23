package vsockwatch

import (
	"context"
	"errors"
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
