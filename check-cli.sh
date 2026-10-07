#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Smoke-tests the CLI with combinations of its options: every combination of
# the protocol, the output, and --repeat must measure successfully, and
# conflicting or invalid options must be rejected. The measurements use an
# external server, so they need network access.
#
# Usage: ./check-cli.sh [path to ttfb]
#
# Without a path, it builds and runs ttfb with cargo.

set -euo pipefail

if [ $# -gt 0 ]; then
    TTFB=("$1")
else
    TTFB=(cargo run --quiet --features bin --)
fi

# Supports HTTP/1.1, HTTP/2, and HTTP/3.
URL=https://www.cloudflare.com

fail() {
    echo "$*" >&2
    exit 1
}

# Runs ttfb with the given arguments, which clap must reject with a usage
# error.
check_rejected() {
    echo "Checking rejection: ttfb $*"
    local status=0
    "${TTFB[@]}" "$@" >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 2 ]; then
        fail "Expected exit code 2 of a usage error, got $status"
    fi
}

protocols=(--http1.1 --http2 --http3 --auto-protocol)
for ((i = 0; i < ${#protocols[@]}; i++)); do
    for ((j = i + 1; j < ${#protocols[@]}; j++)); do
        check_rejected "${protocols[i]}" "${protocols[j]}" "$URL"
    done
done
check_rejected -4 -6 "$URL"
check_rejected --json --headers "$URL"
check_rejected --timeout 0 "$URL"
check_rejected --timeout 3601 "$URL"
check_rejected --repeat 0 "$URL"
check_rejected --repeat 0s "$URL"
check_rejected --repeat x "$URL"
check_rejected

# Empty values stand for omitting the option.
for protocol in "" --http1.1 --http2 --http3 --auto-protocol; do
    case $protocol in
        --http1.1) expected=HTTP/1.1 ;;
        --http2) expected=HTTP/2 ;;
        --http3) expected=HTTP/3 ;;
        # The automatic selection depends on the network. The network tests
        # check it.
        *) expected= ;;
    esac
    for mode in "" --headers --json; do
        for repeat in "" --repeat=2 --repeat=1s; do
            args=(${protocol:+"$protocol"} ${mode:+"$mode"}
                ${repeat:+"$repeat"} "$URL")
            echo "Checking: ttfb ${args[*]}"
            output=$("${TTFB[@]}" "${args[@]}") ||
                fail "Unexpected failure: $output"

            if [ "$mode" = --json ]; then
                jq -e --arg protocol "$expected" '
                    .error == null
                    and .measurements_num >= 1
                    and ($protocol == "" or .first_response.protocol == $protocol)
                    and (.first_response.headers["content-type"] | length) >= 1
                ' <<<"$output" >/dev/null ||
                    fail "Unexpected output: $output"
                continue
            fi

            if [ -n "$expected" ] &&
                ! grep -q "^Protocol *: $expected" <<<"$output"; then
                fail "Expected protocol $expected: $output"
            fi
            if [ -n "$repeat" ] &&
                ! grep -q "^Measurements *: " <<<"$output"; then
                fail "Expected statistics: $output"
            fi
            if [ "$mode" = --headers ] &&
                ! grep -qi "^content-type: " <<<"$output"; then
                fail "Expected headers: $output"
            fi
        done
    done
done

# The remaining options only configure the measurement, so a single run
# checks them instead of every combination.
echo "Checking: ttfb --json -4 -k --timeout 5 $URL"
output=$("${TTFB[@]}" --json -4 -k --timeout 5 "$URL") ||
    fail "Unexpected failure: $output"
jq -e '
    .error == null
    and .options.ip_version == "ipv4"
    and .options.allow_insecure_certificates == true
    and .options.timeout_ms == 5000
    and (.first_response.ip | test("^[0-9.]+$"))
' <<<"$output" >/dev/null || fail "Unexpected output: $output"

echo "All checks passed."
