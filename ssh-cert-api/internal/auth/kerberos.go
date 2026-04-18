// Package auth verifies SPNEGO Kerberos credentials on incoming HTTPS
// requests and produces an authenticated principal for downstream authz.
// The keytab is loaded once at startup; its file permissions are checked
// to reject group- or world-readable keytabs before the service accepts
// its first request.
package auth

import (
	"encoding/base64"
	"fmt"
	"log"
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
	logging.Debug("Base64 token: %s", token)
	spnegoToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SPNEGO token: %w", err)
	}

	logging.Debug("Kerberos authentication attempted with keytab containing %d entries", len(k.keytab.Entries))
	logging.Debug("SPNEGO token length: %d bytes", len(spnegoToken))
	logging.Debug("SPNEGO token (first 32 bytes): %x", spnegoToken[:min(32, len(spnegoToken))])

	// Try alternative SPNEGO parsing approach
	// Some clients send malformed tokens, so we'll try to be more lenient
	var principal string

	// First, try the standard approach
	isInit, negToken, err := spnego.UnmarshalNegToken(spnegoToken)
	if err != nil {
		logging.Debug("Standard SPNEGO unmarshaling failed: %v", err)

		// Try to extract Kerberos AP-REQ directly from the token
		// Skip SPNEGO wrapper and look for Kerberos AP-REQ pattern
		if len(spnegoToken) > 20 {
			// Look for AP-REQ tag (0x6e) in the token
			for i := 0; i < len(spnegoToken)-4; i++ {
				if spnegoToken[i] == 0x6e {
					apReqStart := i
					logging.Debug("Found potential AP-REQ at offset %d", apReqStart)

					// Try to parse as AP-REQ directly
					var apReq messages.APReq
					err = apReq.Unmarshal(spnegoToken[apReqStart:])
					if err == nil {
						logging.Debug("Successfully parsed AP-REQ directly")
						// Verify the AP-REQ using the service settings
						valid, creds, err := service.VerifyAPREQ(&apReq, k.settings)
						if err == nil && valid {
							principal = creds.CName().PrincipalNameString()
							if creds.Realm() != "" {
								principal = fmt.Sprintf("%s@%s", principal, creds.Realm())
							}
							break
						} else {
							logging.Debug("AP-REQ verification failed: %v", err)
						}
					}
				}
			}
		}

		if principal == "" {
			return nil, fmt.Errorf("failed to parse SPNEGO token and extract AP-REQ: %w", err)
		}
	} else {
		// Standard SPNEGO processing worked
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

		// Parse the AP-REQ from the mechanism token
		var apReq messages.APReq
		err = apReq.Unmarshal(negInit.MechTokenBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal AP-REQ: %w", err)
		}

		// Verify the AP-REQ using the service settings
		valid, creds, err := service.VerifyAPREQ(&apReq, k.settings)
		if err != nil || !valid {
			return nil, fmt.Errorf("AP-REQ verification failed: %w", err)
		}

		// Extract the client principal from the credentials
		principal = creds.CName().PrincipalNameString()
		if creds.Realm() != "" {
			principal = fmt.Sprintf("%s@%s", principal, creds.Realm())
		}
	}

	log.Printf("Authenticated principal: %s", principal)

	parts := strings.Split(principal, "@")
	username := parts[0]
	realm := ""
	if len(parts) > 1 {
		realm = parts[1]
	}

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

func (k *KerberosAuthenticator) Authenticate(token string) (string, error) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Negotiate "+token)

	user, err := k.AuthenticateRequest(req)
	if err != nil {
		return "", err
	}

	if user.Realm != "" {
		return fmt.Sprintf("%s@%s", user.Username, user.Realm), nil
	}
	return user.Username, nil
}
