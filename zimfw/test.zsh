#!/usr/bin/env zsh
# gmellon zimfw module — zsh test suite.
#
# Run directly:  ./test.zsh     (or: zsh zimfw/test.zsh)
#
# Uses only test doubles and fixtures:
#   - real AF_UNIX listening sockets, held by socket-holder.zsh (zsh/net/socket)
#   - a stub systemctl earlier in PATH that records every invocation to a log
#     and behaves per $GMELLON_TEST_STUB_MODE:
#       unused   — exits 0, no output (for asserting it was never called)
#       empty    — show-environment: OK, no SSH_AUTH_SOCK; set-environment: OK
#       present  — show-environment: OK, includes SSH_AUTH_SOCK=/existing/systemd/agent
#       fail     — exits 1 (user manager unavailable)
#   - a stub gmellon binary emitting known completion text (completion
#     regeneration cases), run against a writable copy of the module so the
#     checkout is never mutated
#
# Exits nonzero with a failure count summary if any assertion fails.

emulate zsh

MODULE_DIR=${0:A:h}
PASS=0
FAIL=0
FAILED_NAMES=()

WORK=$(mktemp -d "${TMPDIR:-/tmp}/gmellon-zimfw-tests.XXXXXX")
STUB_BIN="${WORK}/stub-bin"
STUB_LOG="${WORK}/systemctl.log"
STUB_MODE='unused'
GMELLON_STUB="${WORK}/gmellon-stub"
MODULE_COPY="${WORK}/module-copy"
STUB_COMPLETIONS=$'#compdef gmellon\n# STUB gmellon completions output'
CASE_ENVS=()
# Defaults every existing case relies on; the completion cases override.
CASE_MODULE="${MODULE_DIR}/init.zsh"
CASE_PATH="${STUB_BIN}:${PATH}"
socket_pids=()

cleanup() {
  (( ${#socket_pids} )) && kill ${socket_pids} 2>/dev/null
  rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- fixtures --

make_socket() {
  # make_socket <socket-path> -> REPLY_SOCKET: real listening socket at path.
  # The path must be the exact agent location, e.g. <xdg>/gcr/ssh — gcr's
  # socket is literally named "ssh" inside the "gcr" directory.
  # (careful: never name a local "path" — $path is tied to $PATH in zsh)
  local sockpath="$1"
  zsh -f "${MODULE_DIR}/socket-holder.zsh" "${sockpath}" &
  socket_pids+=($!)
  local i
  for i in {1..200}; do
    if [[ -e "${sockpath}.ready" ]]; then
      REPLY_SOCKET=${sockpath}
      return 0
    fi
    # sleep, not `read -t`: read depends on stdin, which may be at EOF
    sleep 0.05
  done
  print -u2 "socket fixture never became ready: ${sockpath}"
  return 1
}

make_systemctl_stub() {
  mkdir -p "${STUB_BIN}"
  cat > "${STUB_BIN}/systemctl" <<'STUB'
#!/usr/bin/env zsh
print -r -- "$*" >> "$GMELLON_TEST_STUB_LOG"
case "${GMELLON_TEST_STUB_MODE:-unused}" in
  fail)
    print -u2 -- "Failed to connect to bus: No medium found"
    exit 1
    ;;
  present)
    if [[ $1 == --user && $2 == show-environment ]]; then
      print -r -- "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
      print -r -- "SSH_AUTH_SOCK=/existing/systemd/agent"
    fi
    exit 0
    ;;
  *) # unused, empty
    if [[ $1 == --user && $2 == show-environment && ${GMELLON_TEST_STUB_MODE:-unused} == empty ]]; then
      print -r -- "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
    fi
    exit 0
    ;;
esac
STUB
  chmod +x "${STUB_BIN}/systemctl"
}

# A stub gmellon binary: emits known completion text for exactly the
# `completions zsh` invocation the module makes, fails loudly otherwise.
make_gmellon_stub() {
  mkdir -p "${GMELLON_STUB}"
  cat > "${GMELLON_STUB}/gmellon" <<'STUB'
#!/usr/bin/env zsh
if [[ $1 == completions && $2 == zsh ]]; then
  print -r -- '#compdef gmellon'
  print -r -- '# STUB gmellon completions output'
  exit 0
fi
print -u2 -- "stub gmellon: unexpected invocation: $*"
exit 1
STUB
  chmod +x "${GMELLON_STUB}/gmellon"
}

# A writable copy of the module for completion tests, so regeneration
# writes into the copy and never mutates this checkout. functions/ exists
# (as it does in the shipped module) but no compfile: tests create or
# preload it per case.
copy_module() {
  rm -rf "${MODULE_COPY}"
  mkdir -p "${MODULE_COPY}/functions"
  cp "${MODULE_DIR}/init.zsh" "${MODULE_COPY}/init.zsh"
}

# Run a probe in a clean `zsh -f` with the module available as
# $GMELLON_TEST_MODULE, the stub systemctl first in PATH, SSH_AUTH_SOCK,
# GMELLON_SSH_AUTH_SOCK, and XDG_RUNTIME_DIR stripped, then CASE_ENVS applied.
# CASE_MODULE overrides which init.zsh is sourced (the completion tests use
# a writable module copy); CASE_PATH overrides the probe PATH (the
# completion tests compose a stub gmellon in or out). Captures stdout ->
# REPLY_OUT, stderr -> REPLY_ERR, status -> REPLY_RC.
run_module() {
  local probe=$1
  : > "${WORK}/err"
  REPLY_OUT=$(env -u SSH_AUTH_SOCK -u GMELLON_SSH_AUTH_SOCK -u XDG_RUNTIME_DIR \
    GMELLON_TEST_MODULE="${CASE_MODULE}" \
    PATH="${CASE_PATH}" \
    GMELLON_TEST_STUB_LOG="${STUB_LOG}" \
    GMELLON_TEST_STUB_MODE="${STUB_MODE}" \
    ${CASE_ENVS[@]} \
    zsh -f -c "${probe}" 2> "${WORK}/err")
  REPLY_RC=$?
  REPLY_ERR=$(<"${WORK}/err")
}

stub_calls() {
  [[ -e "${STUB_LOG}" ]] && REPLY_STUB=$(<"${STUB_LOG}") || REPLY_STUB=''
}

# Extract the last "RC=<n>" line a probe printed into REPLY_RC_LINE.
probe_rc() {
  local -a lines
  lines=(${(M)${(f)REPLY_OUT}:#RC=*})
  REPLY_RC_LINE=${lines[-1]:-RC=<none>}
}

# ------------------------------------------------------------ assertions --

assert_eq() {
  # assert_eq <name> <expected> <actual>
  if [[ $2 == $3 ]]; then
    (( PASS++ ))
    print -r -- "ok   - $1"
  else
    (( FAIL++ ))
    FAILED_NAMES+=("$1")
    print -r -- "FAIL - $1"
    print -r -- "  expected: ${(q)2}"
    print -r -- "  actual:   ${(q)3}"
  fi
}

assert_contains() {
  # assert_contains <name> <haystack> <needle>
  if [[ $2 == *$3* ]]; then
    (( PASS++ ))
    print -r -- "ok   - $1"
  else
    (( FAIL++ ))
    FAILED_NAMES+=("$1")
    print -r -- "FAIL - $1"
    print -r -- "  missing: ${(q)3}"
    print -r -- "  in:      ${(q)2}"
  fi
}

assert_not_contains() {
  # assert_not_contains <name> <haystack> <needle>
  if [[ $2 != *$3* ]]; then
    (( PASS++ ))
    print -r -- "ok   - $1"
  else
    (( FAIL++ ))
    FAILED_NAMES+=("$1")
    print -r -- "FAIL - $1"
    print -r -- "  unexpectedly found: ${(q)3}"
    print -r -- "  in:                  ${(q)2}"
  fi
}

# ------------------------------------------------------------------ setup --

make_systemctl_stub
: > "${STUB_LOG}"

FX_GCR="${WORK}/fx-gcr"; mkdir -p "${FX_GCR}/gcr"
FX_KEYRING="${WORK}/fx-keyring"; mkdir -p "${FX_KEYRING}/keyring"
FX_OTHER="${WORK}/fx-other"; mkdir -p "${FX_OTHER}"
FX_EMPTY="${WORK}/fx-empty"; mkdir -p "${FX_EMPTY}"

GCR_SOCK=''; make_socket "${FX_GCR}/gcr/ssh"  && GCR_SOCK=${REPLY_SOCKET}
KEYRING_SOCK=''; make_socket "${FX_KEYRING}/keyring/ssh" && KEYRING_SOCK=${REPLY_SOCKET}
OTHER_SOCK=''; make_socket "${FX_OTHER}/agent" && OTHER_SOCK=${REPLY_SOCKET}

print -r -- "gmellon zimfw module test suite"
print -r -- "module: ${MODULE_DIR}/init.zsh"
print -r -- "fixtures: gcr=${GCR_SOCK} keyring=${KEYRING_SOCK} other=${OTHER_SOCK}"
[[ -S ${GCR_SOCK} && -S ${KEYRING_SOCK} && -S ${OTHER_SOCK} ]] || {
  print -u2 "fixtures are not real sockets; aborting"
  exit 2
}
print -r -- ""

# ------------------------------------------------------------------ tests --

# 1. unset SSH_AUTH_SOCK -> discovered from gcr
STUB_MODE='unused'
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"; print -r -- "VALUE=${SSH_AUTH_SOCK-unset}"'
assert_eq "unset->discovered: exit status 0" 0 ${REPLY_RC}
assert_contains "unset->discovered: exports gcr socket" "${REPLY_OUT}" "VALUE=${GCR_SOCK}"
assert_contains "unset->discovered: reports discovery" "${REPLY_OUT}" "(discovered gcr/ssh)"

# 2. gcr absent -> keyring fallback, documented order
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_KEYRING})
run_module 'source "$GMELLON_TEST_MODULE"; print -r -- "VALUE=${SSH_AUTH_SOCK-unset}"'
assert_eq "keyring-fallback: exit status 0" 0 ${REPLY_RC}
assert_contains "keyring-fallback: exports keyring socket" "${REPLY_OUT}" "VALUE=${KEYRING_SOCK}"
assert_contains "keyring-fallback: reports discovery" "${REPLY_OUT}" "(discovered keyring/ssh)"

# 3. existing valid SSH_AUTH_SOCK -> preserved, silently
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR} SSH_AUTH_SOCK=${OTHER_SOCK})
run_module 'source "$GMELLON_TEST_MODULE"; print -r -- "VALUE=${SSH_AUTH_SOCK-unset}"'
assert_eq "already-set: exit status 0" 0 ${REPLY_RC}
assert_contains "already-set: value preserved" "${REPLY_OUT}" "VALUE=${OTHER_SOCK}"
assert_not_contains "already-set: no export message (stays quiet)" "${REPLY_OUT}" "gmellon: SSH_AUTH_SOCK="

# 4. explicit override wins over existing and discovery
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR} SSH_AUTH_SOCK=${OTHER_SOCK} GMELLON_SSH_AUTH_SOCK=${KEYRING_SOCK})
run_module 'source "$GMELLON_TEST_MODULE"; print -r -- "VALUE=${SSH_AUTH_SOCK-unset}"'
assert_eq "override-wins: exit status 0" 0 ${REPLY_RC}
assert_contains "override-wins: override value exported" "${REPLY_OUT}" "VALUE=${KEYRING_SOCK}"
assert_contains "override-wins: reports override" "${REPLY_OUT}" "(override GMELLON_SSH_AUTH_SOCK)"

# 5. invalid override -> actionable error, environment unchanged, non-fatal
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR} SSH_AUTH_SOCK=${OTHER_SOCK} GMELLON_SSH_AUTH_SOCK=${FX_EMPTY}/does-not-exist)
run_module 'source "$GMELLON_TEST_MODULE"; print -r -- "VALUE=${SSH_AUTH_SOCK-unset}"'
assert_eq "invalid-override: exit status 0 (non-fatal)" 0 ${REPLY_RC}
assert_contains "invalid-override: existing value untouched" "${REPLY_OUT}" "VALUE=${OTHER_SOCK}"
assert_contains "invalid-override: actionable error" "${REPLY_ERR}" "not an existing unix socket"
assert_contains "invalid-override: error names the override" "${REPLY_ERR}" "GMELLON_SSH_AUTH_SOCK"
assert_not_contains "invalid-override: no export performed" "${REPLY_OUT}" "gmellon: SSH_AUTH_SOCK="

# 6. no socket anywhere -> actionable message, nothing exported, non-fatal
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_EMPTY})
run_module 'source "$GMELLON_TEST_MODULE"; print -r -- "VALUE=${SSH_AUTH_SOCK-unset}"'
assert_eq "missing-socket: exit status 0 (non-fatal)" 0 ${REPLY_RC}
assert_contains "missing-socket: nothing exported" "${REPLY_OUT}" "VALUE=unset"
assert_contains "missing-socket: names gcr path" "${REPLY_ERR}" "/gcr/ssh"
assert_contains "missing-socket: names keyring path" "${REPLY_ERR}" "/keyring/ssh"
assert_contains "missing-socket: names the override escape hatch" "${REPLY_ERR}" "GMELLON_SSH_AUTH_SOCK"
assert_contains "missing-socket: names what to enable" "${REPLY_ERR}" "gcr-ssh-agent"

# 7. no socket and XDG_RUNTIME_DIR unset -> still actionable, non-fatal
CASE_ENVS=()
run_module 'source "$GMELLON_TEST_MODULE"; print -r -- "VALUE=${SSH_AUTH_SOCK-unset}"'
assert_eq "xdg-unset: exit status 0 (non-fatal)" 0 ${REPLY_RC}
assert_contains "xdg-unset: nothing exported" "${REPLY_OUT}" "VALUE=unset"
assert_contains "xdg-unset: message still names expected paths" "${REPLY_ERR}" "gcr/ssh"

# 8. existing SSH_AUTH_SOCK that does not validate -> discovery proceeds
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR} SSH_AUTH_SOCK=${FX_GCR}/no-such-socket)
run_module 'source "$GMELLON_TEST_MODULE"; print -r -- "VALUE=${SSH_AUTH_SOCK-unset}"'
assert_contains "stale-existing: discovery fixes stale value" "${REPLY_OUT}" "VALUE=${GCR_SOCK}"

# 9. repeated load in one shell -> same stable value
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"; v1=${SSH_AUTH_SOCK}; source "$GMELLON_TEST_MODULE"; v2=${SSH_AUTH_SOCK}; print -r -- "V1=${v1}"; print -r -- "V2=${v2}"'
assert_contains "repeated-load: first value" "${REPLY_OUT}" "V1=${GCR_SOCK}"
assert_contains "repeated-load: second value identical" "${REPLY_OUT}" "V2=${GCR_SOCK}"

# 10. loading never invokes systemctl (discovery and override paths)
: > "${STUB_LOG}"
STUB_MODE='unused'
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"'
stub_calls
assert_eq "never-systemctl: zero systemctl calls on load (discovery)" "" "${REPLY_STUB}"
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR} GMELLON_SSH_AUTH_SOCK=${KEYRING_SOCK})
run_module 'source "$GMELLON_TEST_MODULE"'
stub_calls
assert_eq "never-systemctl: zero systemctl calls on load (override)" "" "${REPLY_STUB}"

# 11. opt-in publisher: systemd lacks SSH_AUTH_SOCK -> publishes selected value
: > "${STUB_LOG}"
STUB_MODE='empty'
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"; gmellon-ssh-auth-sock-publish-systemd; print -r -- "RC=$?"'
probe_rc; assert_eq "systemd-absent: publisher exit status 0" "RC=0" "${REPLY_RC_LINE}"
stub_calls
assert_contains "systemd-absent: reads show-environment" "${REPLY_STUB}" "--user show-environment"
assert_contains "systemd-absent: sets exactly the selected value" "${REPLY_STUB}" "--user set-environment SSH_AUTH_SOCK=${GCR_SOCK}"
assert_contains "systemd-absent: reports publication" "${REPLY_OUT}" "published SSH_AUTH_SOCK=${GCR_SOCK}"

# 12. opt-in publisher: systemd already has SSH_AUTH_SOCK -> preserved exactly
: > "${STUB_LOG}"
STUB_MODE='present'
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"; gmellon-ssh-auth-sock-publish-systemd; print -r -- "RC=$?"'
probe_rc; assert_eq "systemd-present: publisher exit status 0" "RC=0" "${REPLY_RC_LINE}"
stub_calls
assert_contains "systemd-present: reads show-environment" "${REPLY_STUB}" "--user show-environment"
assert_not_contains "systemd-present: never calls set-environment" "${REPLY_STUB}" "set-environment"
assert_contains "systemd-present: reports exact preserved value" "${REPLY_OUT}" "already has SSH_AUTH_SOCK=/existing/systemd/agent; preserved exactly"

# 13. opt-in publisher: user manager unavailable -> report, no change
: > "${STUB_LOG}"
STUB_MODE='fail'
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"; gmellon-ssh-auth-sock-publish-systemd; print -r -- "RC=$?"; print -r -- "VALUE=${SSH_AUTH_SOCK-unset}"'
probe_rc; assert_eq "systemd-unavailable: publisher exit status 1" "RC=1" "${REPLY_RC_LINE}"
stub_calls
assert_not_contains "systemd-unavailable: never calls set-environment" "${REPLY_STUB}" "set-environment"
assert_contains "systemd-unavailable: reports unavailable manager" "${REPLY_ERR}" "user manager unavailable"
assert_contains "systemd-unavailable: shell environment uncorrupted" "${REPLY_OUT}" "VALUE=${GCR_SOCK}"

# 14. opt-in publisher: nothing selected -> nothing to publish
: > "${STUB_LOG}"
STUB_MODE='empty'
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_EMPTY})
run_module 'source "$GMELLON_TEST_MODULE"; gmellon-ssh-auth-sock-publish-systemd; print -r -- "RC=$?"'
probe_rc; assert_eq "systemd-nothing: publisher exit status 1" "RC=1" "${REPLY_RC_LINE}"
stub_calls
assert_eq "systemd-nothing: systemctl never invoked" "" "${REPLY_STUB}"
assert_contains "systemd-nothing: reports nothing to publish" "${REPLY_ERR}" "nothing to publish"

# 15. opt-in publisher: invalid override blocks publication too
: > "${STUB_LOG}"
STUB_MODE='empty'
CASE_ENVS=(GMELLON_SSH_AUTH_SOCK=${FX_EMPTY}/bogus)
run_module 'source "$GMELLON_TEST_MODULE"; gmellon-ssh-auth-sock-publish-systemd; print -r -- "RC=$?"'
probe_rc; assert_eq "systemd-invalid-override: publisher exit status 1" "RC=1" "${REPLY_RC_LINE}"
stub_calls
assert_eq "systemd-invalid-override: systemctl never invoked" "" "${REPLY_STUB}"
assert_contains "systemd-invalid-override: actionable error shown" "${REPLY_ERR}" "not an existing unix socket"

# --------------------------------------------------- completions (gmellon) --
# The module's second, independently guarded behavior: regenerate
# <module>/functions/_gmellon from the gmellon binary when the binary is
# newer than the compfile (or the compfile is missing). Fixtures: a stub
# gmellon emitting known completion text, and a writable module copy so
# regeneration never touches this checkout.
make_gmellon_stub

# 16. binary present, compfile missing -> regenerated from the stub
: > "${STUB_LOG}"
STUB_MODE='unused'
copy_module
CASE_MODULE="${MODULE_COPY}/init.zsh"
CASE_PATH="${STUB_BIN}:${GMELLON_STUB}:/usr/bin:/bin"
touch -d '2020-01-01 00:00:00' "${GMELLON_STUB}/gmellon"
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"; rc=$?; print -r -- "SRCRC=${rc} VALUE=${SSH_AUTH_SOCK-unset}"'
assert_eq "completions-missing: load exit status 0" 0 ${REPLY_RC}
assert_contains "completions-missing: sourcing is non-fatal" "${REPLY_OUT}" "SRCRC=0"
assert_contains "completions-missing: SSH env still initialized" "${REPLY_OUT}" "VALUE=${GCR_SOCK}"
assert_eq "completions-missing: compfile created" "yes" "$([[ -e ${MODULE_COPY}/functions/_gmellon ]] && print yes || print no)"
REPLY_COMP=$(<"${MODULE_COPY}/functions/_gmellon")
assert_eq "completions-missing: regenerated content is the stub output" "${STUB_COMPLETIONS}" "${REPLY_COMP}"
assert_contains "completions-missing: one-time regeneration note" "${REPLY_ERR}" "Regenerated completions"

# 17. compfile newer than the binary -> untouched
copy_module
print -r -- 'SENTINEL: compfile is fresh' >| "${MODULE_COPY}/functions/_gmellon"
touch -d '2021-01-01 00:00:00' "${MODULE_COPY}/functions/_gmellon"
touch -d '2020-01-01 00:00:00' "${GMELLON_STUB}/gmellon"
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"; rc=$?; print -r -- "SRCRC=${rc} VALUE=${SSH_AUTH_SOCK-unset}"'
assert_contains "completions-fresh: sourcing is non-fatal" "${REPLY_OUT}" "SRCRC=0"
REPLY_COMP=$(<"${MODULE_COPY}/functions/_gmellon")
assert_eq "completions-fresh: fresh compfile untouched" "SENTINEL: compfile is fresh" "${REPLY_COMP}"
assert_not_contains "completions-fresh: no regeneration note" "${REPLY_ERR}" "Regenerated completions"

# 18. binary newer than the compfile -> regenerated
copy_module
print -r -- 'SENTINEL: compfile is stale' >| "${MODULE_COPY}/functions/_gmellon"
touch -d '2019-01-01 00:00:00' "${MODULE_COPY}/functions/_gmellon"
touch -d '2020-01-01 00:00:00' "${GMELLON_STUB}/gmellon"
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"; rc=$?; print -r -- "SRCRC=${rc} VALUE=${SSH_AUTH_SOCK-unset}"'
assert_contains "completions-stale: sourcing is non-fatal" "${REPLY_OUT}" "SRCRC=0"
REPLY_COMP=$(<"${MODULE_COPY}/functions/_gmellon")
assert_eq "completions-stale: stale compfile regenerated" "${STUB_COMPLETIONS}" "${REPLY_COMP}"
assert_contains "completions-stale: regeneration note shown" "${REPLY_ERR}" "Regenerated completions"

# 19. no gmellon on PATH -> no regeneration, SSH env init still runs
copy_module
CASE_PATH="${STUB_BIN}:/usr/bin:/bin"
CASE_ENVS=(XDG_RUNTIME_DIR=${FX_GCR})
run_module 'source "$GMELLON_TEST_MODULE"; rc=$?; print -r -- "SRCRC=${rc} VALUE=${SSH_AUTH_SOCK-unset}"'
assert_eq "completions-absent: load exit status 0" 0 ${REPLY_RC}
assert_contains "completions-absent: sourcing is non-fatal" "${REPLY_OUT}" "SRCRC=0"
assert_contains "completions-absent: SSH env init still ran" "${REPLY_OUT}" "VALUE=${GCR_SOCK}"
assert_contains "completions-absent: discovery still reported" "${REPLY_OUT}" "(discovered gcr/ssh)"
assert_eq "completions-absent: no compfile created" "no" "$([[ -e ${MODULE_COPY}/functions/_gmellon ]] && print yes || print no)"
assert_not_contains "completions-absent: silent skip (no note)" "${REPLY_ERR}" "Regenerated completions"

# 20. loading in every completion case never invokes systemctl
stub_calls
assert_eq "completions-never-systemctl: zero systemctl calls" "" "${REPLY_STUB}"

# Restore the shared defaults for any appended cases.
CASE_MODULE="${MODULE_DIR}/init.zsh"
CASE_PATH="${STUB_BIN}:${PATH}"

# ----------------------------------------------------------------- summary --

print -r -- ""
print -r -- "passed: ${PASS}  failed: ${FAIL}"
if (( FAIL )); then
  print -r -- "failing assertions:"
  for name in "${FAILED_NAMES[@]}"; do
    print -r -- "  - ${name}"
  done
  exit 1
fi
exit 0
