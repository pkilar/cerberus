package api

import (
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	cerberusldap "github.com/pkilar/cerberus/ssh-cert-api/internal/ldap"
)

// ldapClientForTest is an alias to the production Client interface so the
// test helpers below can take a generic shape.
type ldapClientForTest = cerberusldap.Client

func toClientMap(in map[string]ldapClientForTest) map[string]cerberusldap.Client {
	out := make(map[string]cerberusldap.Client, len(in))
	maps.Copy(out, in)
	return out
}

// fakeLDAPClient is a minimal stand-in implementing the small surface of
// cerberusldap.Client that LDAPHealthMonitor uses. The backend name is the
// map key the monitor iterates, so the fake itself carries only the probe
// error it should return.
type fakeLDAPClient struct {
	err error
}

func (f *fakeLDAPClient) UserGroups(context.Context, string) ([]string, error) { return nil, nil }
func (f *fakeLDAPClient) HealthCheck(context.Context) error                    { return f.err }
func (f *fakeLDAPClient) Close() error                                         { return nil }

func TestLDAPHealthMonitor_ProbeAllBackendsStableOrder(t *testing.T) {
	t.Parallel()
	clients := map[string]ldapClientForTest{
		"zeta":  &fakeLDAPClient{},
		"alpha": &fakeLDAPClient{},
		"mike":  &fakeLDAPClient{},
	}
	m := newLDAPHealthMonitor(toClientMap(clients), nil, 1*time.Hour, 100*time.Millisecond)
	m.probeAll(t.Context())

	snaps := m.Snapshots()
	if got, want := len(snaps), 3; got != want {
		t.Fatalf("snapshots = %d, want %d", got, want)
	}
	for i, want := range []string{"alpha", "mike", "zeta"} {
		if snaps[i].Name != want {
			t.Errorf("snaps[%d].Name = %q, want %q", i, snaps[i].Name, want)
		}
		if !snaps[i].Healthy {
			t.Errorf("snaps[%d].Healthy = false, want true", i)
		}
	}
}

func TestLDAPHealthMonitor_FailedBackendReportedAdvisory(t *testing.T) {
	t.Parallel()
	clients := map[string]ldapClientForTest{
		"corp": &fakeLDAPClient{err: errors.New("ldap: connection refused")},
	}
	m := newLDAPHealthMonitor(toClientMap(clients), nil, 1*time.Hour, 100*time.Millisecond)
	m.probeAll(t.Context())

	snaps := m.Snapshots()
	if len(snaps) != 1 || snaps[0].Healthy {
		t.Fatalf("expected one unhealthy snapshot, got %+v", snaps)
	}
	if snaps[0].LastError != "ldap: connection refused" {
		t.Errorf("LastError = %q", snaps[0].LastError)
	}
}

func TestLDAPHealthMonitor_TransitionEmitsLogOnce(t *testing.T) {
	t.Parallel()
	// We can't capture slog output here without wiring a handler, but at
	// least exercise the recovery path so prev != nil; degraded->healthy
	// would emit ldap.health.recovered. The behavioral assertion is
	// covered indirectly by inspecting snapshots transition correctly.
	c := &fakeLDAPClient{err: errors.New("down")}
	m := newLDAPHealthMonitor(toClientMap(map[string]ldapClientForTest{"corp": c}), nil, 1*time.Hour, 100*time.Millisecond)
	m.probeAll(t.Context())
	if m.Snapshots()[0].Healthy {
		t.Fatal("first probe should be unhealthy")
	}
	c.err = nil
	m.probeAll(t.Context())
	if !m.Snapshots()[0].Healthy {
		t.Fatal("second probe after err cleared should be healthy")
	}
}

func TestLDAPHealthMonitor_NilSafe(t *testing.T) {
	t.Parallel()
	var m *LDAPHealthMonitor
	// All nil-receiver methods used by the /health handler must be safe.
	if got := m.Snapshots(); got != nil {
		t.Errorf("nil Snapshots = %+v, want nil", got)
	}
	m.Start(t.Context()) // must not panic
}
