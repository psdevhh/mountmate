#!/bin/zsh
# Automated cycle test for a real encrypted external volume.
#
# `diskutil apfs lockVolume` puts the volume in the locked state a fresh
# plug-in presents, then `diskutil mount` drives a full silent
# unlock+mount through the same privileged path macOS's diskmanagementd
# uses (the attach-time GUI agent path cannot be triggered without
# physically replugging). Every cycle must be silent, and the keychain
# entry is fingerprinted to detect any writer touching it between cycles.
#
# MountMate must not be running: its auto-mount blockers would veto the
# final mount and pollute the verdict.
#
# Usage: scripts/drive-cycle-test.sh <volume-name-or-uuid> [cycles=5]

set -uo pipefail

VOL="${1:?usage: drive-cycle-test.sh <volume-name-or-uuid> [cycles]}"
CYCLES="${2:-5}"
TIMEOUT_SECS=25

if pgrep -x MountMate >/dev/null 2>&1; then
  echo "❌ MountMate is running — quit it first (its auto-mount blockers skew results)" >&2
  exit 2
fi

UUID="$(diskutil info "$VOL" 2>/dev/null | awk '/Volume UUID/ {print $3; exit}')"
if [[ -z "$UUID" ]]; then
  echo "❌ could not resolve volume '$VOL'" >&2
  exit 2
fi
echo "Volume: $VOL  uuid=$UUID  cycles=$CYCLES"

LOG="$(mktemp /tmp/drive-cycle-log.XXXXXX)"
/usr/bin/log stream --style compact --info \
  --predicate "process == \"APFSUserAgent\" OR (subsystem == \"com.apple.securityd\" AND eventMessage CONTAINS[c] \"prompt\")" \
  > "$LOG" 2>&1 &
LOGPID=$!
trap 'kill $LOGPID 2>/dev/null' EXIT
sleep 2

fingerprint() {
  security dump-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null \
    | grep -B10 "\"svce\"<blob>=\"$UUID\"" \
    | awk '/cdat|mdat/ {printf "%s ", $0}'
}

mount_state() {
  diskutil info -plist "$UUID" 2>/dev/null | plutil -extract MountPoint raw -o - - 2>/dev/null
}

BASE_FP="$(fingerprint)"
echo "keychain fingerprint: ${BASE_FP:-<none>}"
FAILED=0

for i in $(seq 1 "$CYCLES"); do
  echo "--- cycle $i/$CYCLES"

  # Start from the locked, unmounted state (what a fresh plug-in presents).
  diskutil unmount "$UUID" >/dev/null 2>&1
  diskutil apfs lockVolume "$UUID" >/dev/null 2>&1
  sleep 1

  mark=$(wc -c < "$LOG")
  mounted=""
  deadline=$((SECONDS + TIMEOUT_SECS))
  diskutil mount "$UUID" >/dev/null 2>&1 &
  MOUNTPID=$!
  while (( SECONDS < deadline )); do
    [[ -n "$(mount_state)" ]] && { mounted=yes; break; }
    sleep 0.5
  done
  kill $MOUNTPID 2>/dev/null; wait $MOUNTPID 2>/dev/null

  segment="$(tail -c +$((mark + 1)) "$LOG")"
  anomalies="$(print -r -- "$segment" | grep -cE 'SecItemCopyMatching failed|displaying keychain prompt')"

  if [[ -n "$mounted" && "$anomalies" -eq 0 ]]; then
    verdict="✅ silent unlock + mount"
  elif [[ -n "$mounted" ]]; then
    verdict="⚠️  mounted, but unlock path not clean (anomalies=$anomalies)"
  else
    verdict="❌ not mounted within ${TIMEOUT_SECS}s"
    FAILED=1
  fi

  fp="$(fingerprint)"
  fp_note="keychain unchanged"
  if [[ "$fp" != "$BASE_FP" ]]; then
    fp_note="KEYCHAIN CHANGED: ${BASE_FP:-<none>} -> ${fp:-<none>}"
    BASE_FP="$fp"
  fi
  echo "$verdict | $fp_note"
  if [[ "$FAILED" -eq 1 || "$fp_note" != "keychain unchanged" ]]; then
    echo "Aborting after cycle $i: $verdict ($fp_note). Full log: $LOG"
    exit 1
  fi
done

# Leave the volume unlocked and unmounted, as we found it.
diskutil unmount "$UUID" >/dev/null 2>&1
echo "All $CYCLES cycles silent. Log: $LOG"
exit 0
