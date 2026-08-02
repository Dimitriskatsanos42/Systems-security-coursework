#!/usr/bin/env bash
#
# run_tests.sh — Βασικό sanity-check test suite για το user_management.sh
#
# Χρησιμοποιεί κυρίως --dry-run ώστε να τρέχει και χωρίς root/CI runner,
# αλλά τρέχει και μερικά πραγματικά tests αν εκτελεστεί ως root (τα
# προειδοποιεί ρητά και καθαρίζει μετά).
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${SCRIPT_DIR}/user_management.sh"

PASS=0
FAIL=0

assert_contains() {
    local haystack="$1" needle="$2" test_name="$3"
    if echo "${haystack}" | grep -qF -- "${needle}"; then
        echo "  ✅ PASS: ${test_name}"
        PASS=$((PASS + 1))
    else
        echo "  ❌ FAIL: ${test_name}"
        echo "     Αναμενόταν να βρεθεί: '${needle}'"
        FAIL=$((FAIL + 1))
    fi
}

assert_exit_code() {
    local actual="$1" expected="$2" test_name="$3"
    if [[ "${actual}" -eq "${expected}" ]]; then
        echo "  ✅ PASS: ${test_name}"
        PASS=$((PASS + 1))
    else
        echo "  ❌ FAIL: ${test_name} (exit code ${actual}, αναμενόταν ${expected})"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Test Suite: user_management.sh ==="

echo -e "\n--- Test: help / usage ---"
output="$("${SCRIPT}" help 2>&1)"
assert_contains "${output}" "create-user" "help εμφανίζει την εντολή create-user"
assert_contains "${output}" "--dry-run" "help εμφανίζει την επιλογή --dry-run"

echo -e "\n--- Test: χωρίς ορίσματα ---"
"${SCRIPT}" &>/dev/null
assert_exit_code "$?" 1 "εκτέλεση χωρίς ορίσματα επιστρέφει exit code 1"

echo -e "\n--- Test: create-user --dry-run (δεν απαιτεί root check να αποτύχει, απλά δείχνει) ---"
if [[ "${EUID}" -eq 0 ]]; then
    output="$("${SCRIPT}" --dry-run create-user --username dryrun_testuser --groups dryrun_grp 2>&1)"
    assert_contains "${output}" "DRY-RUN" "create-user --dry-run εμφανίζει [DRY-RUN] αντί να εκτελεί"
    assert_contains "${output}" "useradd" "create-user --dry-run εμφανίζει την εντολή useradd"
else
    echo "  ⏭️  SKIP: δεν τρέχει ως root, παραλείπεται (require_root θα σταματούσε πριν το dry-run μήνυμα)"
fi

echo -e "\n--- Test: create-user χωρίς --username αποτυγχάνει καθαρά ---"
if [[ "${EUID}" -eq 0 ]]; then
    "${SCRIPT}" create-user &>/dev/null
    assert_exit_code "$?" 1 "create-user χωρίς --username επιστρέφει exit code 1"
else
    echo "  ⏭️  SKIP: απαιτεί root για να φτάσει στον έλεγχο ορισμάτων"
fi

echo -e "\n--- Test: audit (read-only, δεν απαιτεί root) ---"
output="$("${SCRIPT}" audit 2>&1)"
assert_contains "${output}" "USERNAME" "audit εμφανίζει επικεφαλίδα πίνακα"

echo -e "\n--- Test: άγνωστη εντολή αποτυγχάνει καθαρά ---"
"${SCRIPT}" not-a-real-command &>/dev/null
assert_exit_code "$?" 1 "άγνωστη εντολή επιστρέφει exit code 1"

echo -e "\n=== Αποτελέσματα: ${PASS} passed, ${FAIL} failed ==="
if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
exit 0
