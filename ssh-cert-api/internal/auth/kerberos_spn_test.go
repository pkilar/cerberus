package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/types"
)

// The scenario behind these tests: clients reach the API under one name
// (HTTP/cerberus1.dev.example.com, the host's FQDN) while the keytab was
// exported for the service's canonical name (HTTP/cerberus-dev.example.com).
// In Active Directory both SPNs hang off one account and therefore share one
// key, so decryption succeeds as long as the verifier looks up the keytab
// entry named by service_principal instead of the SPN inside the ticket.
// RC4-HMAC keys derive from the password alone (no principal salt), which is
// what lets two differently-named keytab entries carry the identical key here.
const (
	spnTestRealm       = "EXAMPLE.COM"
	spnTestConfigured  = "HTTP/cerberus-dev.example.com"
	spnTestTicketSPN   = "HTTP/cerberus1.dev.example.com"
	spnTestSharedPass  = "shared-account-password"
	spnTestClientCName = "alice"
)

// mintAPReqForSPN builds a service ticket for ticketSPN encrypted with the
// shared key, wrapped in an AP-REQ from alice@EXAMPLE.COM.
func mintAPReqForSPN(t *testing.T, ticketSPN string) messages.APReq {
	t.Helper()
	mintKT := keytab.New()
	if err := mintKT.AddEntry(ticketSPN, spnTestRealm, spnTestSharedPass, time.Now(), 1, etypeID.RC4_HMAC); err != nil {
		t.Fatalf("AddEntry(mint): %v", err)
	}
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spnTestClientCName)
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, ticketSPN)
	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cname, spnTestRealm, sname, spnTestRealm, types.NewKrbFlags(),
		mintKT, etypeID.RC4_HMAC, 1, now, now, now.Add(time.Hour), now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}
	auth, err := types.NewAuthenticator(spnTestRealm, cname)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		t.Fatalf("NewAPReq: %v", err)
	}
	return apReq
}

// writeKeytabWithSPN writes a 0600 keytab holding only spn (shared key).
func writeKeytabWithSPN(t *testing.T, spn string) string {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(spn, spnTestRealm, spnTestSharedPass, time.Now(), 1, etypeID.RC4_HMAC); err != nil {
		t.Fatalf("AddEntry(verify): %v", err)
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "service.keytab")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServicePrincipal_SelectsKeytabEntryRegardlessOfTicketSPN(t *testing.T) {
	ktPath := writeKeytabWithSPN(t, spnTestConfigured)
	for _, configured := range []string{spnTestConfigured, spnTestConfigured + "@" + spnTestRealm} {
		t.Run(configured, func(t *testing.T) {
			k, err := NewKerberosAuthenticator(ktPath, configured)
			if err != nil {
				t.Fatalf("NewKerberosAuthenticator: %v", err)
			}
			apReq := mintAPReqForSPN(t, spnTestTicketSPN)
			ok, creds, err := service.VerifyAPREQ(&apReq, k.settings)
			if err != nil || !ok {
				t.Fatalf("a ticket for %s must verify with the key of configured %s: ok=%v err=%v", spnTestTicketSPN, configured, ok, err)
			}
			if got := creds.CName().PrincipalNameString(); got != spnTestClientCName {
				t.Fatalf("client = %q, want %q", got, spnTestClientCName)
			}
		})
	}
}

func TestServicePrincipal_UnsetFallsBackToTicketSPN(t *testing.T) {
	// Documents the default: with service_principal empty, the verifier looks
	// for the SPN named in the ticket, so a keytab exported for a different
	// name fails with a message that names the SPN the client asked for.
	ktPath := writeKeytabWithSPN(t, spnTestConfigured)
	k, err := NewKerberosAuthenticator(ktPath, "")
	if err != nil {
		t.Fatalf("NewKerberosAuthenticator: %v", err)
	}
	apReq := mintAPReqForSPN(t, spnTestTicketSPN)
	ok, _, err := service.VerifyAPREQ(&apReq, k.settings)
	if ok || err == nil || !strings.Contains(err.Error(), spnTestTicketSPN) {
		t.Fatalf("expected a keytab lookup failure naming %s, got ok=%v err=%v", spnTestTicketSPN, ok, err)
	}

	// And the keytab exported for the ticket's own SPN works without config.
	ktPath = writeKeytabWithSPN(t, spnTestTicketSPN)
	k, err = NewKerberosAuthenticator(ktPath, "")
	if err != nil {
		t.Fatalf("NewKerberosAuthenticator: %v", err)
	}
	ok, _, err = service.VerifyAPREQ(&apReq, k.settings)
	if err != nil || !ok {
		t.Fatalf("default lookup by ticket SPN must succeed: ok=%v err=%v", ok, err)
	}
}
