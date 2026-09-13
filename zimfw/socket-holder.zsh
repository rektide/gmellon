#!/usr/bin/env zsh
# Test fixture: hold a real AF_UNIX listening socket at $1 until killed.
#
# Writes a "<path>.ready" marker file once the listener exists. Connections
# are accepted and dropped. Used only by test.zsh and the load demo — it is
# never sourced or executed by the module itself.
zmodload zsh/net/socket

zsocket -l "$1"
typeset -g serverfd=$REPLY
print -r -- ok >! "$1.ready"

while :; do
  zsocket -a ${serverfd}
done
