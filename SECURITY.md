# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately in one of two ways:

- Use GitHub's private vulnerability reporting: go to the **Security** tab, then click **Report a vulnerability**.
- Email pkilar@gmail.com.

A good report includes:

- the affected component (`ssh-cert-api`, `ssh-cert-signer`, `cssh`, `cerberus-session` or `cerberus-vsock-watch`)
- the version or commit
- what an attacker needs before the attack: network access, a valid Kerberos or OIDC identity, root on the parent instance, or local access to a client machine
- steps to reproduce
- a proposed fix, if you have one

## Supported versions

Fixes go to `main` and ship in the next release. Only the latest release gets security fixes.

## Scope

[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) describes the trust boundaries, the security invariants and the accepted residual risks. [`.oss-scanner/threat_model.md`](.oss-scanner/threat_model.md) summarises them, including how severity is rated and what is out of scope. A report about a risk the threat model already accepts, such as `SIGN-1`, is still welcome if it shows an attack that goes beyond the documented residual risk.
