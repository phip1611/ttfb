#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Checks the format of `ttfb --json` with jq, as scripts depend on it. The
# checks measure external servers, so they need network access.
#
# Usage: ./check-json-output.sh [path to ttfb]
#
# Without a path, it builds and runs ttfb with cargo.

set -euo pipefail

if [ $# -gt 0 ]; then
    TTFB=("$1")
else
    TTFB=(cargo run --quiet --features bin --)
fi

# Runs ttfb with the remaining arguments and checks its JSON output with the
# jq filter in the first argument, which must evaluate to true.
check() {
    local filter=$1
    shift
    echo "Checking: ttfb $*"
    local output
    output=$("${TTFB[@]}" "$@")
    if ! jq -e "$filter" <<<"$output" >/dev/null; then
        echo "Unexpected output: $output" >&2
        exit 1
    fi
}

check '
    .schema_version == 1
    and (.ttfb_version | length) > 0
    and .options.input == "https://github.com"
    and .options.protocol == "auto"
    and .options.ip_version == "any"
    and .options.allow_insecure_certificates == false
    and .options.timeout_ms == 10000
    and .options.repeat.times == 1
    and (.started_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T"))
    and .started_at_unix_ms > 0
    and .error == null
    and .measurements_num == 1
    and .first_response.status == 200
    and .first_response.protocol_selection == "auto"
    and (.first_response.headers["content-type"] | length) >= 1
    and .statistics_ms.ttfb.relative.median > 0
    and .statistics_ms.ttfb.absolute.median > .statistics_ms.ttfb.relative.median
    and .statistics_ms.http_content_download.absolute.median >= .statistics_ms.ttfb.absolute.median
' --json https://github.com

check '
    .measurements_num == 3
    and .options.repeat.times == 3
    and ([.statistics_ms[][] | .min <= .median and .median <= .max] | all)
' --json --repeat 3 https://github.com

# Steps that didn't happen, here the DNS lookup and the TLS handshake, are
# missing in the statistics.
check '
    (.statistics_ms | has("dns_lookup") | not)
    and (.statistics_ms | has("tls_handshake") | not)
    and .statistics_ms.tcp_connect.relative.median > 0
    and .first_response.protocol_selection == "explicit"
    and .options.protocol == "HTTP/1.1"
' --json --http1.1 http://1.1.1.1

# An error must still produce valid JSON, but a failing exit code.
echo "Checking: ttfb --json http://127.0.0.1:1"
if output=$("${TTFB[@]}" --json http://127.0.0.1:1); then
    echo "Unexpected success: $output" >&2
    exit 1
fi
if ! jq -e '
    .error.kind == "tcp_connect"
    and (.error.message | length) > 0
    and .measurements_num == 0
    and .statistics_ms == {}
    and .first_response == null
' <<<"$output" >/dev/null; then
    echo "Unexpected output: $output" >&2
    exit 1
fi

# --json already contains the headers, so --headers is rejected.
echo "Checking: ttfb --json --headers https://github.com"
if "${TTFB[@]}" --json --headers https://github.com >/dev/null 2>&1; then
    echo "Unexpected success of --json with --headers" >&2
    exit 1
fi

echo "All checks passed."
