#!/bin/bash
# Serve a mocked copy of the page on :8767, start headless Chrome on CDP :9337, run the given page tests.
# Every process started here is killed by PID at the end.
set -u
# No suite names = nothing would run and the exit would still be 0 (found 7 Oct). Refuse it.
[ $# -eq 0 ] && { echo "usage: bash run.sh <suite.mjs>... (e.g. \$(ls *.mjs))"; exit 2; }
APP="${VV_APP:-$(cd "$(dirname "$0")/../.." && pwd)}"
# A Chrome still closing from the last run kept 9337, the new one bound elsewhere, and the suites
# talked to the dying one - all 12 "failed" on clean code (8 Oct 2026). Wait up to 30 s, then refuse.
for i in $(seq 1 30); do netstat -ano | grep -qE ":(9337|8767) .*LISTEN" || break; sleep 1; done
netstat -ano | grep -qE ":(9337|8767) .*LISTEN" && { echo "HARNESS: port 9337 or 8767 still in use"; exit 3; }
SP="${VV_SCRATCH:-$TEMP/vv-pagetest}"; mkdir -p "$SP"
W="$SP/web"
rm -rf "$W" "$SP/chrome-prof" && mkdir -p "$W" || exit 1
cp -r "$APP/src/." "$W/" && cp "$APP/tests/page/scan-calls-mock.js" "$W/mock.js" || exit 1
sed -i 's#<script type="module" src="main.js"></script>#<script src="mock.js"></script><script type="module" src="main.js"></script>#' "$W/index.html"
grep -q 'src="mock.js"' "$W/index.html" || { echo "mock not injected"; exit 1; }
echo 'window.__t = { scanIntro, scanFlow, summarize, fullScanIntro, offlineIntro, hacked, checkFile, laptopDoses, deeperDoses, checkup, state, sweepIntro, sweepStart, sweepWatch, sweepFinish, sweepClean, allDoses, doseState, renderCard, setTick, moreChecks, refreshKnown, phoneHacked, phoneSweep, refreshFolders, folderRow, sweepFoldersNow, allFlow, applyAll, sysFixOf, showHow, analyze };' >> "$W/main.js"
python -m http.server 8767 --directory "$W" > "$SP/http.log" 2>&1 &
HTTP=$!
"C:/Program Files/Google/Chrome/Application/chrome.exe" --headless=new --remote-debugging-port=9337 --user-data-dir="$SP/chrome-prof" --no-first-run "http://127.0.0.1:8767/index.html" > "$SP/chrome.log" 2>&1 &
CH=$!
# Wait for Chrome's debugging port instead of a fixed sleep; no browser = no verdict (exit 3), never "tests failed".
up=0; for i in $(seq 1 30); do curl -s -m 2 http://127.0.0.1:9337/json/version > /dev/null && { up=1; break; }; sleep 1; done
[ $up -eq 1 ] || echo "HARNESS: Chrome never answered on 9337"
rc=0
for t in "$@"; do
  [ $up -eq 1 ] || { rc=3; break; }
  node "$APP/tests/page/$t" 9337 > "$SP/$t.log" 2>&1; r=$?
  # A browser that died mid-run makes every later suite fail for the same non-reason (8 Oct 2026).
  grep -q "ECONNREFUSED 127.0.0.1:9337" "$SP/$t.log" && { echo "== $t HARNESS: lost the browser"; rc=3; break; }
  echo "== $t exit=$r"; tail -25 "$SP/$t.log"
  [ $r -ne 0 ] && rc=1
done
# Chrome's own children: kill the tree of the PID we started (its Windows pid), then the server.
WPID=$(ps -W -p $CH 2>/dev/null | awk 'NR==2{print $4}')
[ -n "$WPID" ] && taskkill //PID $WPID //T //F > /dev/null 2>&1
HW=$(ps -W -p $HTTP 2>/dev/null | awk 'NR==2{print $4}'); [ -n "$HW" ] && taskkill //PID $HW //F > /dev/null 2>&1; kill $CH $HTTP 2>/dev/null
echo "chrome winpid=$WPID killed; http pid=$HTTP killed"
# The Chrome profile and served copy are ~3,000 files; leave nothing in Temp (Fix 1, 25 Sep).
sleep 1; rm -rf "$W" "$SP/chrome-prof"
exit $rc
