package vsockwatch

import (
	"context"
	"testing"
	"time"
)

func withFakeAuditRules(t *testing.T, sequence [][]string) {
	t.Helper()
	i := 0
	orig := listAuditRules
	listAuditRules = func(context.Context) ([]string, error) {
		if i >= len(sequence) {
			i = len(sequence) - 1
		}
		lines := sequence[i]
		i++
		return lines, nil
	}
	t.Cleanup(func() { listAuditRules = orig })
}

func TestAuditRulePresent(t *testing.T) {
	withFakeAuditRules(t, [][]string{
		{`-a always,exit -F arch=b64 -S connect -k cerberus_vsock_watch`},
	})
	present, err := AuditRulePresent(context.Background())
	if err != nil {
		t.Fatalf("AuditRulePresent: %v", err)
	}
	if !present {
		t.Error("expected the rule to be reported present")
	}
}

func TestAuditRulePresent_NotPresent(t *testing.T) {
	withFakeAuditRules(t, [][]string{
		{`-a always,exit -F arch=b64 -S execve -k some_other_rule`},
	})
	present, err := AuditRulePresent(context.Background())
	if err != nil {
		t.Fatalf("AuditRulePresent: %v", err)
	}
	if present {
		t.Error("expected the rule to be reported absent")
	}
}

func TestTamperWatch_AlertsOnDisappearance(t *testing.T) {
	withFakeAuditRules(t, [][]string{
		{`-k cerberus_vsock_watch`}, // present
		{`-k cerberus_vsock_watch`}, // still present
		{`-k some_other_rule`},      // disappeared -> alert
		{`-k some_other_rule`},      // stays absent -> no repeat alert
	})
	shipper := &fakeShipper{}
	tw := &TamperWatch{Shipper: shipper, Interval: 5 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_ = tw.RunAuditRuleCheck(ctx)

	if shipper.count() != 1 {
		t.Fatalf("got %d tamper alerts, want exactly 1 (no repeat spam)", shipper.count())
	}
	if shipper.alerts[0].Kind != KindDetectorTamper {
		t.Errorf("Kind = %q, want %q", shipper.alerts[0].Kind, KindDetectorTamper)
	}
	if shipper.alerts[0].Detector != SourceAuditd {
		t.Errorf("Detector = %q, want %q", shipper.alerts[0].Detector, SourceAuditd)
	}
}

func TestTamperWatch_NeverPresent_NoAlert(t *testing.T) {
	withFakeAuditRules(t, [][]string{
		{`-k some_other_rule`},
		{`-k some_other_rule`},
	})
	shipper := &fakeShipper{}
	tw := &TamperWatch{Shipper: shipper, Interval: 5 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = tw.RunAuditRuleCheck(ctx)

	if shipper.count() != 0 {
		t.Fatalf("got %d alerts, want 0 (rule was never observed present, so absence isn't tampering)", shipper.count())
	}
}

type fakeHeartbeatClient struct {
	calls int
	err   error
}

func (f *fakeHeartbeatClient) Do(context.Context, string) error {
	f.calls++
	return f.err
}

func TestHeartbeat_Run_PingsRepeatedly(t *testing.T) {
	client := &fakeHeartbeatClient{}
	h := &Heartbeat{URL: "http://example.invalid/heartbeat", Client: client, Interval: 5 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_ = h.Run(ctx, nil)

	if client.calls < 2 {
		t.Fatalf("got %d heartbeat calls, want at least 2", client.calls)
	}
}

func TestHeartbeat_Run_ErrorDoesNotStopLoop(t *testing.T) {
	client := &fakeHeartbeatClient{err: context.DeadlineExceeded}
	var errCount int
	h := &Heartbeat{URL: "http://example.invalid/heartbeat", Client: client, Interval: 5 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_ = h.Run(ctx, func(error) { errCount++ })

	if client.calls < 2 {
		t.Fatalf("got %d calls, want at least 2 despite errors", client.calls)
	}
	if errCount != client.calls {
		t.Errorf("onError called %d times, want %d (once per failed call)", errCount, client.calls)
	}
}
