// Package auth verifies SPNEGO Kerberos credentials on incoming HTTPS
// requests and produces an authenticated principal for downstream authz.
// The keytab is loaded once at startup; its file permissions are checked
// to reject group- or world-readable keytabs before the service accepts
// its first request.
package auth

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"cerberus/logging"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

type Authenticator interface {
	AuthenticateRequest(r *http.Request) (*AuthenticatedUser, error)
}

var _ Authenticator = (*KerberosAuthenticator)(nil)

type KerberosAuthenticator struct {
	keytab   *keytab.Keytab
	spnego   *spnego.SPNEGO
	settings *service.Settings
}

type AuthenticatedUser struct {
	Username string
	Realm    string
}

func NewKerberosAuthenticator(keytabPath string, servicePrincipal string) (*KerberosAuthenticator, error) {
	if err := checkKeytabPermissions(keytabPath); err != nil {
		return nil, err
	}

	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load keytab from %s: %w", keytabPath, err)
	}

	// Configure service settings with the specified service principal
	var settings *service.Settings
	var spnegoService *spnego.SPNEGO

	if servicePrincipal != "" {
		logging.Debug("Configuring Kerberos authenticator with service principal: %s", servicePrincipal)
		settings = service.NewSettings(kt, service.SName(servicePrincipal))
		spnegoService = spnego.SPNEGOService(kt, service.SName(servicePrincipal))
	} else {
		logging.Debug("Configuring Kerberos authenticator with default service principal from keytab")
		settings = service.NewSettings(kt)
		spnegoService = spnego.SPNEGOService(kt)
	}

	return &KerberosAuthenticator{
		keytab:   kt,
		spnego:   spnegoService,
		settings: settings,
	}, nil
}

func (k *KerberosAuthenticator) AuthenticateRequest(r *http.Request) (*AuthenticatedUser, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	token, ok := strings.CutPrefix(authHeader, "Negotiate ")
	if !ok {
		return nil, fmt.Errorf("authorization header must use Negotiate scheme")
	}
	spnegoToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SPNEGO token: %w", err)
	}

	// Never log the token bytes themselves — even at DEBUG, even truncated,
	// the GSS-API wrapper plus AP-REQ contains principal, service, and a
	// replayable authenticator within the clock-skew window.
	logging.Debug("Kerberos authentication attempted (keytab entries=%d, token_len=%d)", len(k.keytab.Entries), len(spnegoToken))

	isInit, negToken, err := spnego.UnmarshalNegToken(spnegoToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPNEGO token: %w", err)
	}
	if !isInit {
		return nil, fmt.Errorf("expected NegTokenInit, got NegTokenResp")
	}

	negInit, ok := negToken.(spnego.NegTokenInit)
	if !ok {
		return nil, fmt.Errorf("failed to cast to NegTokenInit")
	}

	if len(negInit.MechTokenBytes) == 0 {
		return nil, fmt.Errorf("no mechanism token in SPNEGO")
	}

	var apReq messages.APReq
	if err := apReq.Unmarshal(negInit.MechTokenBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AP-REQ: %w", err)
	}

	valid, creds, err := service.VerifyAPREQ(&apReq, k.settings)
	if err != nil || !valid {
		return nil, fmt.Errorf("AP-REQ verification failed: %w", err)
	}

	// Require a non-empty realm. Falling back to an empty realm silently
	// produces a "user@" key string that won't match any group in config.yaml
	// and would just deny access without a clear reason — fail loudly here
	// so the cause is in the auth log.
	username := creds.CName().PrincipalNameString()
	realm := creds.Realm()
	if realm == "" {
		return nil, fmt.Errorf("kerberos credential has no realm")
	}

	slog.Info("auth.success", "principal", username+"@"+realm)

	return &AuthenticatedUser{
		Username: username,
		Realm:    realm,
	}, nil
}

// checkKeytabPermissions refuses to proceed if the keytab file is readable by
// anyone other than the owner. A world-or-group-readable keytab hands the
// service's Kerberos key to any local user, enabling token forgery.
func checkKeytabPermissions(keytabPath string) error {
	info, err := os.Stat(keytabPath)
	if err != nil {
		return fmt.Errorf("failed to stat keytab %s: %w", keytabPath, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("keytab %s has insecure permissions %#o: must not be group- or world-readable", keytabPath, mode)
	}
	return nil
}
