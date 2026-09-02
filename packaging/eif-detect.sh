#!/usr/bin/env bash
# Shared EIF auto-detection for the three packaging entry points.
#
# Sourced by build-rpm.sh, build-arch.sh and build-deb.sh so the rule for "should
# this build also produce cerberus-signer-eif?" is written once. The three
# packagings are kept deliberately in sync, and a detection rule that drifted
# between them would produce a different set of packages per distribution from
# one working tree -- the least obvious kind of packaging bug.
#
# The trigger is the CA key material the EIF is built from: ssh-cert-signer/
# ca_key.enc (baked into the image, decrypted inside the enclave via an attested
# KMS call) and ssh-cert-signer/ca_key.pub (baked in as the CA_PUBLIC_KEY_PATH
# integrity pin). Both present means this tree is a deployment tree, so the EIF
# package is in scope. Neither present -- the normal case for a CI or upstream
# build -- means it is not, and nothing changes.
#
# SECURITY: everything this file enables ends in a package that carries
# per-deployment CA key material and pins a deployment-specific PCR0. That
# package must reach only an operator-controlled channel, never a shared or
# public repository. Because detection is automatic, the guard below matters:
# key material has to be verified as ciphertext before it can be packaged.

# Map this machine's architecture to the name the EIF artifacts use. Echoes an
# empty string on anything else; callers treat that as "no EIF for this host".
cerberus_host_arch() {
    case "$(uname -m)" in
        x86_64)          printf 'amd64' ;;
        aarch64 | arm64) printf 'arm64' ;;
        *)               printf '' ;;
    esac
}

# Refuse to package a "ciphertext" file that is really a plaintext private key.
#
# make encrypt-ca-key generates ca_key, encrypts it to ca_key.enc under KMS, and
# shreds the plaintext -- but it deliberately PRESERVES the plaintext when the
# KMS call fails, so an interrupted or failed encryption can leave a tree
# holding a real private key. Nothing downstream re-checks: the signer Makefile
# only tests that ca_key.enc is non-empty, the Dockerfile COPYs whatever is
# there, and the enclave would fail to decrypt it at runtime -- long after the
# key was published inside an image.
#
# That was survivable while the EIF package required an explicit --eif flag. It
# is not survivable once presence alone triggers packaging, so the check lands
# here, at the point where automation replaced the operator's judgement.
#
# KMS ciphertext is binary and never PEM-armoured; every plaintext key form we
# could plausibly find here (OPENSSH, RSA, EC, PKCS#8) begins with "-----BEGIN".
# Testing for that exact prefix is decisive in both directions.
cerberus_assert_ciphertext() {
    local f="$1"

    if [[ ! -s "$f" ]]; then
        echo "ERROR: ${f} is empty." >&2
        echo "  A zero-length ca_key.enc usually means 'make encrypt-ca-key' failed part-way." >&2
        return 1
    fi

    # Exactly the length of the marker: "-----BEGIN" is ten bytes (five dashes,
    # five letters). Reading one byte more captures the following space and the
    # comparison silently never matches -- a guard that always passes.
    local magic
    magic="$(head -c 10 "$f" 2>/dev/null | tr -d '\0')"
    if [[ "${magic}" == "-----BEGIN" ]]; then
        cat >&2 <<EOF

  ============================ REFUSING TO BUILD ============================
  ${f}
  is a PLAINTEXT private key, not KMS ciphertext. It begins with "-----BEGIN".

  Packaging it would bake an unencrypted CA private key into the EIF and
  publish it inside cerberus-signer-eif. The enclave could not decrypt it
  either -- it expects a KMS CiphertextBlob -- so this fails at runtime too.

  This is the state 'make encrypt-ca-key' leaves behind when the KMS call
  fails: it preserves the plaintext rather than destroying an un-backed-up
  key. Encrypt it before building:

      cd ssh-cert-signer
      rm -f ca_key.enc                    # the unencrypted copy
      make encrypt-ca-key KMS_KEY_ARN=arn:aws:kms:REGION:ACCOUNT:key/KEY-ID

  Or pass --no-eif to build the ordinary packages without the EIF.
  ===========================================================================

EOF
        return 1
    fi

    return 0
}

# Decide whether this build also produces cerberus-signer-eif, and if so which
# EIF and PCR manifest it uses.
#
# Sets, in the caller's scope:
#   EIF_FILE          absolute path to the EIF to bundle, or "" for none
#   EIF_PCR_MANIFEST  absolute path to the matching PCR manifest, or ""
#
# Returns non-zero only for a refusal the operator must act on (unverifiable key
# material). A missing EIF or missing enclave tooling is reported and skipped:
# the ordinary packages still build. Containerised builds run on distributions
# that ship no nitro-cli at all, and the base packages do not depend on the EIF.
cerberus_eif_autodetect() {
    local root="$1" build_if_missing="${2:-1}"
    local arch enc pub eif manifest signer_dir

    EIF_FILE=""
    EIF_PCR_MANIFEST=""

    signer_dir="${root}/ssh-cert-signer"
    enc="${signer_dir}/ca_key.enc"
    pub="${signer_dir}/ca_key.pub"

    # Both halves, or this is not a deployment tree. ca_key.enc alone is what a
    # half-finished 'make encrypt-ca-key' leaves; ca_key.pub alone is what
    # remains after distributing the public half to SSH servers.
    if [[ ! -f "${enc}" || ! -f "${pub}" ]]; then
        return 0
    fi

    arch="$(cerberus_host_arch)"
    if [[ -z "${arch}" ]]; then
        echo "==> CA key material found, but $(uname -m) has no EIF build target; skipping the EIF package." >&2
        return 0
    fi

    echo "==> CA key material detected (ca_key.enc + ca_key.pub)"
    echo "    This tree is a deployment tree, so cerberus-signer-eif is in scope."

    cerberus_assert_ciphertext "${enc}" || return 1

    eif="${signer_dir}/ssh-cert-signer-${arch}.eif"
    manifest="${signer_dir}/pcr-manifest-${arch}.json"

    if [[ ! -f "${eif}" ]]; then
        if [[ "${build_if_missing}" -eq 1 ]] \
           && command -v nitro-cli >/dev/null 2>&1 \
           && command -v docker >/dev/null 2>&1; then
            echo "==> No ${eif##*/} yet; building it (nitro-cli and docker are available)..."
            # Build in the signer module, exactly as `make eif-<arch>` does, so
            # the PCR manifest is produced by the same code path that a manual
            # build uses and the two can never disagree.
            if ! make -C "${signer_dir}" "eif-${arch}"; then
                echo "ERROR: EIF build failed. Fix it, or pass --no-eif to build without the EIF package." >&2
                return 1
            fi
        else
            echo "!! CA key material is present but ${eif##*/} is missing, and this host" >&2
            echo "!! cannot build one (needs nitro-cli and docker on a Nitro instance)." >&2
            echo "!! Building WITHOUT the EIF package. To include it, run on a Nitro host:" >&2
            echo "!!     make -C ssh-cert-signer eif-${arch}" >&2
            return 0
        fi
    fi

    EIF_FILE="${eif}"
    echo "==> EIF: ${EIF_FILE}"

    if [[ -f "${manifest}" ]]; then
        EIF_PCR_MANIFEST="${manifest}"
        echo "==> PCR manifest: ${EIF_PCR_MANIFEST}"
    else
        # Not fatal: an EIF copied in from another host arrives without its
        # manifest. Say so, because a PCR-conditioned KMS policy cannot be
        # updated without those measurements, and discovering that at deploy
        # time is worse than hearing it now.
        echo "!! No ${manifest##*/} next to the EIF. The package will still build," >&2
        echo "!! but you will need PCR0 from the build host to update a" >&2
        echo "!! PCR-conditioned KMS key policy (docs/kms-attestation-policy.md)." >&2
    fi

    return 0
}

# Print the standing warning about what an EIF package contains. Every entry
# point says this at the same volume, right before the build that produces it.
cerberus_eif_warn() {
    echo "    WARNING: cerberus-signer-eif carries the KMS-encrypted CA key and the"
    echo "             PCR0-pinned public key. It is per-deployment and per-architecture;"
    echo "             publish it only to an operator-controlled channel, never a public repo."
}

# Copy the PCR manifest next to the built packages, so the measurements travel
# with the artifacts they describe. A PCR-conditioned KMS key policy has to be
# updated to the new PCR0 BEFORE the new EIF is deployed; leaving the manifest
# behind in the source tree is how that step gets skipped.
cerberus_save_pcr_manifest() {
    local manifest="$1" dest_dir="$2"

    [[ -n "${manifest}" && -f "${manifest}" ]] || return 0
    mkdir -p "${dest_dir}"
    cp "${manifest}" "${dest_dir}/"
    echo "==> PCR manifest saved: ${dest_dir}/$(basename "${manifest}")"
}
