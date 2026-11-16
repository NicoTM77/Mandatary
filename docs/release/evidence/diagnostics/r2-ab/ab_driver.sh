#!/usr/bin/env bash
# P1.20 R2 A/B measurement driver (EXPERIMENT protocol of the reviewer plan, section 6). Runs the schedule in order,
# interleaved, one release-harness run each (matrix + lifecycle + latency + 40 s load; idle/restore/migration/docs stages skipped),
# optionally with 2 bounded host CPU burners (plain shell loops, `timeout`-bounded, killed by PID afterwards).
# Usage: bash ab_driver.sh <schedule-file> <outdir> ; schedule line: "<arm A|B> <clean|burn> <run-id>"
# SHA_A / SHA_B come from the environment (full shas). Every result is kept; a run that did not produce a results file is logged as ABORTED.
# The schedule is read on fd 3 and every command gets </dev/null: ssh would otherwise swallow the rest of the schedule.
set -u
SCHED=${1:?schedule}; OUT=${2:?outdir}
D=/opt/data/scratch/p120/vm
V=/opt/data/integrations/mandatary-vm/run
SKIP="IDLE-FRESH,IDLE-CONFIGURED,PERSISTENCE,RESTORE,MIGRATION,DEVFLOW,DOCS,LOGLEVEL,LOGS"
mkdir -p "$OUT"
while read -r -u 3 ARM HOST RUNID; do
  [ -z "${ARM:-}" ] && continue
  case "$ARM" in A) SHA=$SHA_A;; B) SHA=$SHA_B;; *) echo "bad arm $ARM"; continue;; esac
  T=/srv/mandatary/tests/p120-${SHA:0:12}
  echo "=== $RUNID arm=$ARM host=$HOST sha=${SHA:0:7} $(date -u +%FT%TZ)" | tee -a "$OUT/driver.log"
  if [ "$HOST" = burn ]; then
    $V "rm -f $T/burn.pids; for b in \$(seq 1 2); do timeout 500 sh -c 'while :; do :; done' >/dev/null 2>&1 & echo \$! >> $T/burn.pids; done; echo burners=\$(wc -l < $T/burn.pids)" < /dev/null | tee -a "$OUT/driver.log"
  fi
  bash $D/push.sh release "$SHA" "--load-seconds 40 --count-requests --skip $SKIP" > /dev/null 2>&1 < /dev/null
  finished=0
  for w in $(seq 1 120); do
    sleep 10
    if bash $D/push.sh relog "$SHA" 3 2>&1 < /dev/null | grep -q FINISHED; then finished=1; break; fi
  done
  if [ "$HOST" = burn ]; then
    $V "for p in \$(cat $T/burn.pids); do kill \$p 2>/dev/null; done; rm -f $T/burn.pids" > /dev/null 2>&1 < /dev/null
  fi
  mkdir -p "$OUT/$RUNID"
  $V "cd $T/logs && tar -czf - release.json release.log 2>/dev/null | base64 -w0" < /dev/null | base64 -d | tar -xzf - -C "$OUT/$RUNID" 2>/dev/null
  if [ -s "$OUT/$RUNID/release.json" ]; then
    echo "$RUNID arm=$ARM host=$HOST sha=${SHA:0:12} finished=$finished json=$(sha256sum "$OUT/$RUNID/release.json" | cut -c1-16)" >> "$OUT/driver.log"
  else
    echo "$RUNID arm=$ARM host=$HOST sha=${SHA:0:12} ABORTED finished=$finished (no results file)" >> "$OUT/driver.log"
  fi
  # a stale release.json must never be mistaken for the next run's
  $V "rm -f $T/logs/release.json $T/logs/release.log" > /dev/null 2>&1 < /dev/null
  echo "$ARM $HOST $RUNID" >> "$OUT/done.list"
  sleep 15
done 3< "$SCHED"
echo "SCHEDULE DONE $(date -u +%FT%TZ)" | tee -a "$OUT/driver.log"
