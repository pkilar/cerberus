package vsockwatch

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAnomalyAlert(t *testing.T) {
	ev := Event{PID: 1, UID: 0, GID: 0, Comm: "evil", Exe: "/tmp/evil", Source: SourceEBPF}
	cls := Classification{Verdict: Anomalous, Reason: "exe mismatch"}
	a := NewAnomalyAlert(ev, cls)
	if a.Kind != KindVSockAnomaly {
		t.Errorf("Kind = %q", a.Kind)
	}
	if a.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", a.Severity)
	}
	if a.Exe != "/tmp/evil" || a.UID != 0 {
		t.Errorf("got %+v", a)
	}
}

func TestNewTamperAlert(t *testing.T) {
	a := NewTamperAlert(SourceAuditd, "auditd rule deleted")
	if a.Kind != KindDetectorTamper {
		t.Errorf("Kind = %q", a.Kind)
	}
	if a.Detector != SourceAuditd {
		t.Errorf("Detector = %q", a.Detector)
	}
}

// countingShipper counts Ship calls and can be made to fail.
type countingShipper struct {
	calls int
	err   error
}

func (c *countingShipper) Ship(context.Context, Alert) error {
	c.calls++
	return c.err
}

func TestShippers_FiresAllIndependently(t *testing.T) {
	a := &countingShipper{err: errors.New("boom")}
	b := &countingShipper{}
	shippers := Shippers{a, b}

	err := shippers.Ship(context.Background(), Alert{Kind: KindVSockAnomaly})
	if err == nil {
		t.Fatal("expected the joined error from the failing shipper")
	}
	if a.calls != 1 || b.calls != 1 {
		t.Fatalf("a.calls=%d b.calls=%d, want both 1 (one failing shipper must not stop the others)", a.calls, b.calls)
	}
}

func TestLogShipper_NeverErrors(t *testing.T) {
	l := LogShipper{}
	if err := l.Ship(context.Background(), NewAnomalyAlert(Event{}, Classification{Verdict: Anomalous})); err != nil {
		t.Fatalf("LogShipper.Ship returned an error: %v", err)
	}
}

func TestWebhookShipper_PostsJSON(t *testing.T) {
	var gotBody Alert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	shipper := WebhookShipper{URL: srv.URL}
	alert := NewAnomalyAlert(Event{PID: 42, Exe: "/tmp/evil"}, Classification{Verdict: Anomalous, Reason: "test"})
	if err := shipper.Ship(context.Background(), alert); err != nil {
		t.Fatalf("Ship: %v", err)
	}
	if gotBody.PID != 42 || gotBody.Exe != "/tmp/evil" {
		t.Errorf("server received %+v", gotBody)
	}
}

func TestWebhookShipper_NoURL(t *testing.T) {
	shipper := WebhookShipper{}
	if err := shipper.Ship(context.Background(), Alert{}); err == nil {
		t.Fatal("expected an error when URL is empty")
	}
}

func TestWebhookShipper_NonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	shipper := WebhookShipper{URL: srv.URL}
	if err := shipper.Ship(context.Background(), Alert{}); err == nil {
		t.Fatal("expected an error for a 500 response")
	}
}
