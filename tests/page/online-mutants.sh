#!/bin/bash
# Page mutants for the online look-up wording. Each: replace one string in main.js, run the one
# suite that should catch it, restore byte-for-byte (hash checked).
APP="${VV_APP:-$(cd "$(dirname "$0")/../.." && pwd)}"
F="$APP/src/main.js"
cd "$APP" || exit 1
git diff --quiet -- src/main.js 2>/dev/null; # main.js may be dirty (uncommitted work) - we back up, not git-restore
cp "$F" "$F.mutbak" || exit 1
H0=$(sha256sum "$F" | cut -d' ' -f1)
# Killed part-way (29 Sep: a tool timeout did exactly that) -> put main.js back anyway.
trap '[ -f "$F.mutbak" ] && cp "$F.mutbak" "$F" && rm -f "$F.mutbak"' EXIT
OUT="$APP/tests/page/online-mutants.result"; : > "$OUT"
run() { # name suite from to
  python - "$F" "$3" "$4" <<'PY'
import sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(p, 'rb').read().decode('utf-8')
n = t.count(a)
if n != 1:
    print("SKIPPED: pattern count", n); sys.exit(3)
open(p, 'wb').write(t.replace(a, b).encode('utf-8'))
PY
  rc=$?
  if [ $rc -eq 3 ]; then echo "MUTANT $1: SKIPPED"; cp "$F.mutbak" "$F"; return; fi
  bash tests/page/run.sh "$2" > "$TEMP/pmut.log" 2>&1
  if grep -q "^== $2 exit=0" "$TEMP/pmut.log"; then echo "MUTANT $1: SURVIVED" | tee -a "$OUT"; else echo "MUTANT $1: RED" | tee -a "$OUT"; fi
  cp "$F.mutbak" "$F"
}
run "slip drops Reported by" folders.mjs 'const said = x.online ? `${what} Reported by: ${x.online}.` : what;' 'const said = what;'
run "online note says nothing" folders.mjs 'if (!o?.ran || !asked) return "";' 'return "";'
run "failed count hidden" folders.mjs '(o.failed ? ` ${n(o.failed)} could not be asked' '(false ? ` ${n(o.failed)} could not be asked'
run "online app credited to MalwareBazaar (row)" known.mjs 'filter((f) => !f.stalkerware && !f.online).map((f) => appOf(s, f));' 'filter((f) => !f.stalkerware).map((f) => appOf(s, f));'
run "online app Stop words" known.mjs 'const onl = found.filter((f) => f.online && !f.stalkerware);' 'const onl = [];'
run "single file bad not danger" fileinside.mjs '  if (o?.said === "bad") {
    levels.push("danger");' '  if (o?.said === "bad") {'
run "single file failure not said" fileinside.mjs '} else if (o && !o.said && o.error) {' '} else if (false) {'
run "single file receipt line gone" fileinside.mjs 'if (on?.said) li.push(' 'if (false) li.push('
H1=$(sha256sum "$F" | cut -d' ' -f1)
rm -f "$F.mutbak"
[ "$H0" = "$H1" ] && echo "restored: hash matches" || echo "RESTORE MISMATCH"
