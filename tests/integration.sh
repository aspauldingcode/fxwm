#!/bin/bash
#
# integration.sh - privileged end-to-end test for Doorman.
#
# Proves that the framework (through its CLI) can create a real macOS account,
# authenticate/log in to it, launch a session as that user, and that the stock
# Unix/macOS tools (id, dscl, dscacheutil) fully interoperate with the account.
#
# Must run as root:  sudo ./tests/integration.sh
# Expects the build to already exist (run `make` first).

# Note: intentionally no `set -e`. Each step is recorded via check() and the
# script continues so we get a full pass/fail summary; the final exit code
# reflects whether any check failed.
set -uo pipefail

BINDIR="${BINDIR:-build/bin}"
DOORMAN="$BINDIR/doorman"

if [[ $EUID -ne 0 ]]; then
  echo "integration.sh must run as root (sudo)"; exit 1
fi
if [[ ! -x "$DOORMAN" ]]; then
  echo "missing $DOORMAN - run 'make' first"; exit 1
fi

SUFFIX="$$"
USER_NAME="doormant_${SUFFIX}"
GROUP_NAME="doormang_${SUFFIX}"
PW="D00rman-Test-${SUFFIX}"
PW2="D00rman-Changed-${SUFFIX}"

pass=0; fail=0
check() { # check "desc" <exit-status-of-previous-via-$?>
  if [[ "$2" -eq 0 ]]; then echo "ok   - $1"; pass=$((pass+1));
  else echo "FAIL - $1"; fail=$((fail+1)); fi
}

cleanup() {
  "$DOORMAN" userdel -r "$USER_NAME" >/dev/null 2>&1 || \
    dscl . -delete "/Users/$USER_NAME" >/dev/null 2>&1 || true
  rm -rf "/Users/$USER_NAME" 2>/dev/null || true
  "$DOORMAN" groupdel "$GROUP_NAME" >/dev/null 2>&1 || \
    dseditgroup -o delete "$GROUP_NAME" >/dev/null 2>&1 || true
  dscacheutil -flushcache 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Doorman integration test (user=$USER_NAME) ==="

# 1. Create a user with the Linux-style CLI, backed by the framework.
"$DOORMAN" useradd -m -c "Doorman Test" -s /bin/zsh -p "$PW" "$USER_NAME"; check "useradd creates user" $?
dscacheutil -flushcache || true

# 2. The stock Unix tools see the doorman-created account (interop).
id "$USER_NAME" >/dev/null 2>&1; check "system 'id' sees the account" $?
dscl . -read "/Users/$USER_NAME" UniqueID >/dev/null 2>&1; check "system 'dscl -read' sees the account" $?
test -d "/Users/$USER_NAME"; check "home directory created (macOS template)" $?
test -d "/Users/$USER_NAME/Library"; check "home has macOS template (~/Library)" $?

# 3. Authenticate through the framework CLI (reads password from stdin).
printf '%s\n' "$PW" | "$DOORMAN" authenticate "$USER_NAME" >/dev/null; check "doorman authenticate succeeds" $?

# 4. The system authenticator agrees against the same account (interop).
dscl . -authonly "$USER_NAME" "$PW" >/dev/null 2>&1; check "system 'dscl -authonly' agrees" $?

# 5. Wrong password must fail.
if printf '%s\n' "wrong-${PW}" | "$DOORMAN" authenticate "$USER_NAME" >/dev/null 2>&1; then
  check "wrong password rejected" 1
else
  check "wrong password rejected" 0
fi

# 6. Log in and launch a session as the user; prove privileges were dropped.
WHO="$(printf '%s\n' "$PW" | "$DOORMAN" login "$USER_NAME" --exec '/usr/bin/id -un' 2>/dev/null)"
case "$WHO" in
  *"$USER_NAME"*) check "login opens session as the user (id -un contains $USER_NAME)" 0 ;;
  *) echo "  (got: '$WHO')"; check "login opens session as the user (id -un contains $USER_NAME)" 1 ;;
esac

# 7. Password change through the framework; re-auth with the new password;
#    old password no longer works; system tools see the change.
printf '%s\n' "$PW2" | "$DOORMAN" passwd --stdin "$USER_NAME" >/dev/null; check "doorman passwd changes password" $?
dscacheutil -flushcache || true
printf '%s\n' "$PW2" | "$DOORMAN" authenticate "$USER_NAME" >/dev/null; check "auth with new password" $?
dscl . -authonly "$USER_NAME" "$PW2" >/dev/null 2>&1; check "system 'dscl -authonly' sees new password" $?
if printf '%s\n' "$PW" | "$DOORMAN" authenticate "$USER_NAME" >/dev/null 2>&1; then
  check "old password rejected after change" 1
else
  check "old password rejected after change" 0
fi

# 8. Group creation and membership, then verify with the system tool.
"$DOORMAN" groupadd "$GROUP_NAME"; check "groupadd creates group" $?
"$DOORMAN" usermod -aG "$GROUP_NAME" "$USER_NAME"; check "usermod adds user to group" $?
dseditgroup -o checkmember -m "$USER_NAME" "$GROUP_NAME" >/dev/null 2>&1; check "system 'dseditgroup' sees membership" $?

# 8b. Remove the membership again (gpasswd -d) and confirm it is gone.
"$DOORMAN" gpasswd -d "$USER_NAME" "$GROUP_NAME"; check "gpasswd removes membership" $?
if dseditgroup -o checkmember -m "$USER_NAME" "$GROUP_NAME" >/dev/null 2>&1; then
  check "membership gone after gpasswd -d" 1
else
  check "membership gone after gpasswd -d" 0
fi

# 8c. Delete the group.
"$DOORMAN" groupdel "$GROUP_NAME"; check "groupdel removes the group" $?

# 9. Deletion.
"$DOORMAN" userdel -r "$USER_NAME"; check "userdel removes the account" $?
if id "$USER_NAME" >/dev/null 2>&1; then check "account gone after userdel" 1; else check "account gone after userdel" 0; fi

echo
echo "$pass passed, $fail failed"
rc=0; [[ "$fail" -eq 0 ]] || rc=1
exit "$rc"
