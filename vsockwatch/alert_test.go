package vsockwatch

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestIsSlackWebhookURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://hooks.slack.com/services/T00/B00/xxxx", true},
		{"http://hooks.slack.com/services/T00/B00/xxxx", true},
		{"https://example.com/webhook", false},
		{"https://not-hooks.slack.com.evil.example/x", false},
		{"https://evil.example/hooks.slack.com", false},
		{"not a url at all \x7f", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isSlackWebhookURL(tt.url); got != tt.want {
			t.Errorf("isSlackWebhookURL(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestSlackPayload_Shape(t *testing.T) {
	ev := Event{PID: 42, UID: 0, GID: 0, Comm: "evil", Exe: "/tmp/evil", Source: SourceEBPF}
	a := NewAnomalyAlert(ev, Classification{Verdict: Anomalous, Reason: "exe mismatch"})
	payload := slackPayload(a)

	for _, want := range []string{"CRITICAL", string(KindVSockAnomaly), "exe mismatch", "42", "/tmp/evil", "evil"} {
		if !strings.Contains(payload.Text, want) {
			t.Errorf("slack text %q missing expected substring %q", payload.Text, want)
		}
	}
}

func TestSlackPayload_EscapesUntrustedFields(t *testing.T) {
	ev := Event{Comm: "<b>&pwn</b>", Exe: "/tmp/<script>evil</script>", Source: SourceEBPF}
	a := NewAnomalyAlert(ev, Classification{Verdict: Anomalous, Reason: "exe <injected> & broken"})
	payload := slackPayload(a)

	for _, bad := range []string{"<b>", "<script>", "<injected>"} {
		if strings.Contains(payload.Text, bad) {
			t.Errorf("slack text contains unescaped markup %q: %s", bad, payload.Text)
		}
	}
	for _, want := range []string{"&lt;b&gt;", "&amp;pwn", "&lt;script&gt;", "&lt;injected&gt;", "&amp; broken"} {
		if !strings.Contains(payload.Text, want) {
			t.Errorf("slack text missing escaped form %q: %s", want, payload.Text)
		}
	}
}

func TestWebhookShipper_SlackFormat_SendsTextPayload(t *testing.T) {
	var raw map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	shipper := WebhookShipper{URL: srv.URL, Format: WebhookFormatSlack}
	alert := NewAnomalyAlert(Event{PID: 42, Exe: "/tmp/evil"}, Classification{Verdict: Anomalous, Reason: "test"})
	if err := shipper.Ship(context.Background(), alert); err != nil {
		t.Fatalf("Ship: %v", err)
	}

	text, ok := raw["text"].(string)
	if !ok || text == "" {
		t.Fatalf("expected a non-empty top-level \"text\" field (Slack's required contract), got %+v", raw)
	}
	if _, hasPID := raw["pid"]; hasPID {
		t.Errorf("Slack payload should not carry the raw Alert's fields directly, got %+v", raw)
	}
}

func TestWebhookShipper_ExplicitGenericFormatOverridesSlackURL(t *testing.T) {
	// Even a URL that WOULD auto-detect as Slack must respect an explicit
	// Format override — an operator proxying/relaying through a
	// hooks.slack.com-named endpoint that actually expects the raw JSON.
	var gotBody Alert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	shipper := WebhookShipper{URL: srv.URL, Format: WebhookFormatGeneric}
	alert := NewAnomalyAlert(Event{PID: 7}, Classification{Verdict: Anomalous, Reason: "test"})
	if err := shipper.Ship(context.Background(), alert); err != nil {
		t.Fatalf("Ship: %v", err)
	}
	if gotBody.PID != 7 {
		t.Errorf("got %+v, want the raw Alert JSON despite the URL", gotBody)
	}
}

// TestWebhookShipper_StalledServerDoesNotBlockForever verifies the default
// client (Client left nil) is bounded by webhookTimeout: both detector loops
// call Ship synchronously, so a webhook peer that accepts a connection but
// never responds must not be able to block a detector from consuming any
// further events indefinitely.
func TestWebhookShipper_StalledServerDoesNotBlockForever(t *testing.T) {
	orig := webhookTimeout
	webhookTimeout = 50 * time.Millisecond
	defer func() { webhookTimeout = orig }()

	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond until the test unblocks it
	}))
	defer srv.Close()  // must run after close(block) below (LIFO) or Close hangs
	defer close(block) // registered last -> runs first, unblocking the handler

	shipper := WebhookShipper{URL: srv.URL}
	start := time.Now()
	err := shipper.Ship(context.Background(), Alert{Kind: KindVSockAnomaly})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a webhook peer that never responds")
	}
	if elapsed > time.Second {
		t.Fatalf("Ship took %v to return, want it bounded by webhookTimeout (~%v)", elapsed, webhookTimeout)
	}
}
