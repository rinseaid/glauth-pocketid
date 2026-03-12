#!/bin/bash
# Wrapper for pam_exec.so — exports env vars that pam_exec doesn't inherit
set -a
. /etc/environment
set +a
exec /usr/local/bin/pam-pocketid
