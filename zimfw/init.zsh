# gmellon SSH agent socket selection + zsh completions — zimfw module.
#
# Two independently guarded behaviors:
#
#   1. Exports a validated SSH_AUTH_SOCK in the loading shell. Loading
#      never prompts for a password, never locks or unlocks anything, and
#      never invokes systemctl. Publishing to the systemd user manager is a
#      separate, explicit, opt-in function. None of this depends on the
#      gmellon binary being installed.
#   2. Installs gmellon's zsh completions: when the gmellon binary is on
#      PATH and newer than <module>/functions/_gmellon (or the file is
#      missing), regenerates it with `gmellon completions zsh` and prints
#      one note on stderr. zimfw's default module wiring already puts
#      <module>/functions on fpath for a zmodule line without
#      --fpath/--autoload/--cmd (src/functions/30_zmodule.zsh.erb), so
#      compinit picks the file up with no fpath code of our own.
#
# Selection priority (one code path, shared with the opt-in publisher):
#   1. GMELLON_SSH_AUTH_SOCK override — must validate, otherwise an
#      actionable error and the environment stays unchanged (no discovery).
#   2. an existing SSH_AUTH_SOCK that still resolves to a socket — never
#      clobbered (e.g. a 1Password/gpg agent); also makes repeated loads
#      trivially stable.
#   3. discovery: $XDG_RUNTIME_DIR/gcr/ssh (gcr-ssh-agent), then
#      $XDG_RUNTIME_DIR/keyring/ssh (gnome-keyring's SSH component).
#   4. nothing found — actionable non-fatal message; nothing is exported and
#      the shell does not exit nonzero.
#
# Validation means "path exists and is a unix socket" ([[ -S ]]). It is
# deliberately not a connect probe: a blocked connect on a full accept
# backlog would hang shell startup. A stale socket file whose listener died
# therefore still validates; harmless, and the first real agent use fails
# loudly at that point.

# _gmellon_ssh_auth_sock_valid <path>
# True when <path> is non-empty and an existing unix socket file.
_gmellon_ssh_auth_sock_valid() {
  emulate -L zsh
  [[ -n ${1:-} && -S ${1:-} ]]
}

# _gmellon_ssh_auth_sock_label <reply[1]> — human-readable selection label.
_gmellon_ssh_auth_sock_label() {
  emulate -L zsh
  case ${1:-} in
    override)    print -r -- 'override GMELLON_SSH_AUTH_SOCK' ;;
    existing)    print -r -- 'existing SSH_AUTH_SOCK' ;;
    gcr/ssh)     print -r -- 'discovered gcr/ssh' ;;
    keyring/ssh) print -r -- 'discovered keyring/ssh' ;;
    *)           print -r -- 'selected' ;;
  esac
}

# _gmellon_ssh_auth_sock_select
# The single selection path used by module load and the systemd publisher.
# On success (return 0): global REPLY holds the selected socket path and
# global reply[1] holds the selection reason
# (override | existing | gcr/ssh | keyring/ssh).
# On failure (return 1): an actionable message was already printed where
# applicable; the environment was not modified.
_gmellon_ssh_auth_sock_select() {
  emulate -L zsh
  typeset -g REPLY=''
  typeset -ga reply
  reply=()

  # 1. explicit override wins, but only when it validates
  if [[ -n ${GMELLON_SSH_AUTH_SOCK:-} ]]; then
    if _gmellon_ssh_auth_sock_valid "${GMELLON_SSH_AUTH_SOCK}"; then
      REPLY=${GMELLON_SSH_AUTH_SOCK}
      reply=(override)
      return 0
    fi
    print -u2 -l -r -- \
      "gmellon: GMELLON_SSH_AUTH_SOCK='${GMELLON_SSH_AUTH_SOCK}' is not an existing unix socket." \
      "gmellon: leaving the environment unchanged. Fix the override, or unset it to use discovery."
    reply=(invalid-override)
    return 1
  fi

  # 2. never clobber a working agent
  if [[ -n ${SSH_AUTH_SOCK:-} ]] && _gmellon_ssh_auth_sock_valid "${SSH_AUTH_SOCK}"; then
    REPLY=${SSH_AUTH_SOCK}
    reply=(existing)
    return 0
  fi

  # 3. GNOME/GCR discovery, in documented order
  if [[ -n ${XDG_RUNTIME_DIR:-} ]]; then
    local where
    for where in gcr/ssh keyring/ssh; do
      if _gmellon_ssh_auth_sock_valid "${XDG_RUNTIME_DIR}/${where}"; then
        REPLY="${XDG_RUNTIME_DIR}/${where}"
        reply=(${where})
        return 0
      fi
    done
  fi

  reply=(not-found)
  return 1
}

# _gmellon_ssh_auth_sock_initialize — module load entry point. Never fatal.
_gmellon_ssh_auth_sock_initialize() {
  emulate -L zsh
  local -a msg

  if _gmellon_ssh_auth_sock_select; then
    if [[ ${reply[1]} != existing ]]; then
      export SSH_AUTH_SOCK=${REPLY}
      print -r -- "gmellon: SSH_AUTH_SOCK=${SSH_AUTH_SOCK} ($(_gmellon_ssh_auth_sock_label ${reply[1]}))"
    fi
    # existing valid SSH_AUTH_SOCK: stay quiet, touch nothing
    return 0
  fi

  # nothing selected: actionable, non-fatal
  local xdg=${XDG_RUNTIME_DIR:-'<XDG_RUNTIME_DIR unset>'}
  msg=(
    "gmellon: no usable SSH agent socket found; nothing was exported."
  )
  if [[ -n ${SSH_AUTH_SOCK:-} ]]; then
    msg+=("gmellon: current SSH_AUTH_SOCK='${SSH_AUTH_SOCK}' is not an existing socket; left unchanged.")
  fi
  msg+=(
    "gmellon: expected one of:"
    "gmellon:   ${xdg}/gcr/ssh     (gcr-ssh-agent, GNOME's current SSH agent)"
    "gmellon:   ${xdg}/keyring/ssh (gnome-keyring's SSH agent component)"
    "gmellon: enable one of those agents, or set GMELLON_SSH_AUTH_SOCK to a socket path."
    "gmellon: this module never prompts, never locks or unlocks, and never runs systemctl."
  )
  print -u2 -l -r -- ${msg}
  return 0
}

# gmellon-ssh-auth-sock-publish-systemd — opt-in, never run on load.
#
# Publishes the selected/validated SSH_AUTH_SOCK to the systemd user manager
# environment: reads `systemctl --user show-environment` and only when
# SSH_AUTH_SOCK is absent there, sets it with `systemctl --user
# set-environment`. An existing value is preserved exactly and reported. If
# the user manager is unavailable (systemctl fails), it reports and changes
# nothing. The shell environment itself is never modified.
gmellon-ssh-auth-sock-publish-systemd() {
  emulate -L zsh
  local selected why envout
  local -a matches

  if ! _gmellon_ssh_auth_sock_select; then
    print -u2 -r -- \
      "gmellon: nothing to publish: no validated SSH agent socket is selected."
    return 1
  fi
  selected=${REPLY}
  why=$(_gmellon_ssh_auth_sock_label ${reply[1]})

  if ! envout=$(command systemctl --user show-environment 2>&1); then
    print -u2 -l -r -- \
      "gmellon: 'systemctl --user show-environment' failed (user manager unavailable?); nothing changed." \
      "${envout}"
    return 1
  fi

  matches=(${(M)${(f)envout}:#SSH_AUTH_SOCK=*})
  if (( ${#matches} )); then
    print -r -- "gmellon: systemd user manager already has ${matches[1]}; preserved exactly."
    return 0
  fi

  command systemctl --user set-environment "SSH_AUTH_SOCK=${selected}"
  print -r -- "gmellon: published SSH_AUTH_SOCK=${selected} to the systemd user manager (${why})."
}

_gmellon_ssh_auth_sock_initialize

# --- completions ------------------------------------------------------------
# Separately guarded from the SSH block above: when gmellon is not on PATH
# this returns before the completion work and the SSH environment work
# above has already run (it never depended on the binary). `return 0`
# keeps loading non-fatal in that case too, matching the module contract.
(( ${+commands[gmellon]} )) || return 0

local _zim_gmellon_dir=${0:h}

() {
  local command=${commands[gmellon]}
  local compfile=$1/functions/_gmellon
  if [[ ! -e $compfile || $compfile -ot $command ]]; then
    ${command} completions zsh >| $compfile
    print -u2 -PR "* Detected a new version of 'gmellon'. Regenerated completions."
  fi
} "${_zim_gmellon_dir}"

# Loading is never fatal: a missing socket is a reported condition, not an
# error exit for the shell.
return 0
