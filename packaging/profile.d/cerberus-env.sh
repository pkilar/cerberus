# Cerberus client site configuration — sourced for login shells before cssh runs.
#
# The cerberus-client package ships this file as %config(noreplace): your edits
# here SURVIVE package upgrades. The companion /etc/profile.d/cssh.sh is plain
# code and is REPLACED on upgrade (so fixes always apply) — put site config here,
# not there. Per-user overrides (export in ~/.bashrc / ~/.zshrc) and per-call
# flags (cssh --url / --cacert) still take precedence over these values.
#
# This file sorts before cssh.sh, so these exports are set before the function
# is defined. Uncomment and set your site values.

# Base URL of the Cerberus signing API (/sign is appended). Required by cssh.
#export CERBERUS_URL=https://cerberus.example.com:8443

# CA bundle to trust for the API's TLS certificate. Only needed for a private CA
# that isn't already in the system trust store.
#export CERBERUS_CACERT=/etc/pki/ca-trust/source/anchors/cerberus-ca.pem

# ── OIDC authentication (optional) ────────────────────────────────────────────
# For users without Kerberos. Set CSSH_AUTH=oidc to make cssh authenticate with
# an OIDC identity provider via the device flow (or leave it unset and pass
# --oauth per call). Requires the issuer and a public client registered for the
# OAuth 2.0 Device Authorization Grant. The token is cached under
# ~/.cache/cerberus/ (mode 0600) and refreshed silently.
#export CSSH_AUTH=oidc
#export CSSH_OIDC_ISSUER=https://idp.example.com
#export CSSH_OIDC_CLIENT_ID=cerberus-cssh
# Optional: request scopes (default "openid profile email groups offline_access").
#export CSSH_OIDC_SCOPE="openid profile email groups offline_access"
# Optional: some IdPs (e.g. Auth0) need this so the access token carries the
# Cerberus API audience configured under the server's oauth.audiences.
#export CSSH_OIDC_AUDIENCE=cerberus
