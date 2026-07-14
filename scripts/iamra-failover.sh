#!/bin/sh
# iamra-failover.sh — multi-region failover wrapper for
# `aws_signing_helper credential-process`.
#
# Tries each region's trust anchor/profile ARN pair in order and prints the
# first successful credential JSON to stdout (credential_process contract:
# stdout carries JSON only; all logging goes to stderr).
#
# Failover happens ONLY on retryable errors (throttling, 5xx, network,
# per-attempt timeout). Configuration errors such as AccessDeniedException or
# ValidationException fail immediately without trying the next region, so a
# misconfigured ARN set is surfaced instead of masked.
#
# Required environment variables:
#   CERT             path to the client certificate
#   CERTKEY          path to the private key
#   ROLE_ARN         IAM role ARN (same role in every region)
#   IAMRA_ARN_SETS   comma-separated "<trust-anchor-arn>|<profile-arn>" pairs,
#                    in priority order, e.g.
#                    "arn:aws:rolesanywhere:ap-northeast-2:...:trust-anchor/aaa|arn:aws:rolesanywhere:ap-northeast-2:...:profile/bbb,arn:aws:rolesanywhere:ap-northeast-1:...:trust-anchor/ccc|arn:aws:rolesanywhere:ap-northeast-1:...:profile/ddd"
#
# Optional environment variables:
#   IAMRA_ATTEMPT_TIMEOUT  seconds per attempt (default 15; needs `timeout`)
#   IAMRA_HELPER_BIN       helper binary (default: aws_signing_helper in PATH)
#   IAMRA_EXTRA_ARGS       extra flags appended to every attempt (unquoted
#                          word-split; only use for simple flags)
#
# --region is intentionally not passed: the helper derives the region from the
# trust anchor ARN, so each ARN set is routed to its own regional endpoint.

set -u

log() { printf '[iamra-failover] %s\n' "$*" >&2; }

: "${CERT:?CERT is required (path to client certificate)}"
: "${CERTKEY:?CERTKEY is required (path to private key)}"
: "${ROLE_ARN:?ROLE_ARN is required}"
: "${IAMRA_ARN_SETS:?IAMRA_ARN_SETS is required (comma-separated ta-arn|profile-arn pairs)}"

HELPER="${IAMRA_HELPER_BIN:-aws_signing_helper}"
ATTEMPT_TIMEOUT="${IAMRA_ATTEMPT_TIMEOUT:-15}"

TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout ${ATTEMPT_TIMEOUT}"
fi

ERRFILE=$(mktemp) || { log "mktemp failed"; exit 1; }
trap 'rm -f "$ERRFILE"' EXIT INT TERM

# Errors worth failing over: throttling/quota, server-side 5xx, exhausted SDK
# retries, and network-level failures. Everything else (403 AccessDenied,
# validation, bad key/cert paths, ...) is a configuration problem that the
# next region would reproduce or hide.
is_retryable() {
    grep -Eq 'ThrottlingException|TooManyRequests|StatusCode: 429|StatusCode: 5[0-9][0-9]|InternalServerException|ServiceUnavailable|exceeded maximum number of attempts|dial tcp|i/o timeout|connection refused|connection reset|no such host|TLS handshake timeout|unexpected EOF' "$1"
}

# Split IAMRA_ARN_SETS on commas into positional parameters, then restore IFS
# so the attempt loop word-splits normally (TIMEOUT_CMD relies on it).
OLDIFS=$IFS
IFS=','
set -f
# shellcheck disable=SC2086
set -- $IAMRA_ARN_SETS
set +f
IFS=$OLDIFS

attempt=0
last_rc=1
for arn_set in "$@"; do
    # ARNs never contain whitespace; strip any the user added around commas.
    arn_set=$(printf '%s' "$arn_set" | tr -d '[:space:]')
    [ -n "$arn_set" ] || continue
    attempt=$((attempt + 1))

    trust_anchor_arn=${arn_set%%|*}
    profile_arn=${arn_set#*|}
    if [ -z "$trust_anchor_arn" ] || [ -z "$profile_arn" ] || [ "$trust_anchor_arn" = "$arn_set" ]; then
        log "invalid ARN set #${attempt}: '${arn_set}' (expected '<trust-anchor-arn>|<profile-arn>')"
        exit 1
    fi

    # shellcheck disable=SC2086
    if output=$($TIMEOUT_CMD "$HELPER" credential-process \
            --certificate "$CERT" \
            --private-key "$CERTKEY" \
            --trust-anchor-arn "$trust_anchor_arn" \
            --profile-arn "$profile_arn" \
            --role-arn "$ROLE_ARN" \
            ${IAMRA_EXTRA_ARGS:-} 2>"$ERRFILE"); then
        printf '%s' "$output"
        exit 0
    else
        last_rc=$?
    fi

    # `timeout` exits 124 when the attempt ran too long: retryable.
    if [ "$last_rc" -eq 124 ] || is_retryable "$ERRFILE"; then
        log "attempt ${attempt} (${trust_anchor_arn}) failed with retryable error (rc=${last_rc}): $(head -n 1 "$ERRFILE")"
        continue
    fi

    log "attempt ${attempt} (${trust_anchor_arn}) failed with non-retryable error (rc=${last_rc}); not trying further regions"
    cat "$ERRFILE" >&2
    exit "$last_rc"
done

log "all ${attempt} ARN set(s) exhausted; last error:"
cat "$ERRFILE" >&2
exit "$last_rc"
