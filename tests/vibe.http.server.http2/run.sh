#!/bin/bash
set -e -o pipefail

dub build --compiler=${DC:-dmd} 2>&1

TESTS=$(H2_TEST=list ./tests 2>/dev/null | tr -d '\r')

if [ -z "$TESTS" ]; then
    echo "No HTTP/2 tests to run (curl may lack h2c support)."
    exit 0
fi

FAILED=0

for test in $TESTS; do
    echo -n "[TEST] $test ... "
    OUTPUT=$(H2_TEST="$test" ./tests 2>&1) || true
    if echo "$OUTPUT" | grep -q '\[PASS\]'; then
        echo "PASS"
    else
        echo "FAIL"
        echo "$OUTPUT"
        FAILED=$((FAILED + 1))
    fi
done

if [ $FAILED -gt 0 ]; then
    echo "$FAILED test(s) FAILED."
    exit 1
fi

echo "All HTTP/2 integration tests passed."
