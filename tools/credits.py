"""Builds the in-app Licences and credits page (src/credits.html) and the full licence texts
(src/licenses.txt) FROM WHAT IS ON DISK, so the credits cannot drift from what ships
(LEGAL-CHECK.md O1/O2, his taps 29 Sep 2026 "All free fixes now" + "put some legal notices ...
we credit these people").

Reads: the rule folders' LICENSE files and each YARAhub rule's own licence/author meta, the font
package's LICENSE, Cargo's resolved dependency set for the two shipped targets (Windows, Android)
and each crate's own licence files from the local Cargo registry.

Run:  python tools/credits.py        (from app/; prints counts; exit 1 if anything is missing)
"""
import hashlib, html, json, os, re, subprocess, sys
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
SRC = APP / "src"
TAURI = APP / "src-tauri"
TARGETS = ["x86_64-pc-windows-msvc", "aarch64-linux-android"]
problems = []


def read(p):
    return Path(p).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").strip()


# ---- data and rules bundled in the app --------------------------------------------------------
def yarahub_cc_by():
    """The YARAhub rules that are CC BY 4.0 (the CC0 ones need no credit): file + author."""
    out = []
    # Both YARAhub folders (yarahub-win = the laptop set, 2 Nov 2026), and EVERY rule's licence in a
    # file: one CC BY rule among CC0 ones still needs its credit.
    files = sorted((TAURI / "yara" / "yarahub").glob("*.yar")) + sorted((TAURI / "yara" / "yarahub-win").glob("*.yar"))
    for f in files:
        t = f.read_text(encoding="utf-8", errors="replace")
        lics = re.findall(r'yarahub_license\s*=\s*"([^"]+)"', t)
        if not lics:
            problems.append(f"no yarahub_license in {f.name}")
            continue
        lic = re.search(r'yarahub_license\s*=\s*"((?!CC0 1\.0")[^"]+)"', t) or re.search(r'yarahub_license\s*=\s*"([^"]+)"', t)
        if lic.group(1) != "CC0 1.0":
            uuid = re.search(r'yarahub_uuid\s*=\s*"([^"]+)"', t)
            authors = sorted(set(re.findall(r'\bauthor\s*=\s*"([^"]+)"', t))) or [
                "an author the rule does not name (YARAhub rule " + (uuid.group(1) if uuid else "id not given") + ")"]
            out.append((f.stem, lic.group(1), ", ".join(authors)))
    return out


def rule_licence(folder):
    p = TAURI / "yara" / folder / "LICENSE"
    if not p.exists():
        problems.append(f"missing {p}")
        return ""
    return read(p)


def packer_sources():
    """How many protector names each source gives, read from deeplook.rs's PACKERS itself."""
    t = (TAURI / "src" / "deeplook.rs").read_text(encoding="utf-8")
    m = re.search(r"const PACKERS: &\[\(&str, &str, &str\)\] = &\[(.*?)\n\];", t, re.S)
    if not m:
        problems.append("PACKERS (name, protector, source) not found in deeplook.rs")
        return {}
    n = {}
    for src in re.findall(r'\("[^"]*", "[^"]*", "([^"]*)"\)', m.group(1)):
        n[src] = n.get(src, 0) + 1
    return n


def packer_licence(name):
    p = TAURI / "packers" / f"LICENSE-{name}"
    if not p.exists():
        problems.append(f"missing {p}")
        return ""
    return read(p)


def font_licence():
    p = APP / "node_modules" / "@fontsource" / "atkinson-hyperlegible" / "LICENSE"
    if not p.exists():
        problems.append(f"missing {p} (run npm install)")
        return ""
    return read(p)


# ---- Rust crates actually built for the shipped targets ---------------------------------------
def crates():
    seen = {}
    for tgt in TARGETS:
        r = subprocess.run(["cargo", "metadata", "--format-version", "1", "--offline", "--filter-platform", tgt,
                            "--manifest-path", str(TAURI / "Cargo.toml")], capture_output=True, text=True, encoding="utf-8")
        if r.returncode:
            problems.append(f"cargo metadata failed for {tgt}: {r.stderr[:200]}")
            continue
        m = json.loads(r.stdout)
        pk = {p["id"]: p for p in m["packages"]}
        nodes = {n["id"]: n for n in m["resolve"]["nodes"]}
        # Walk from the app through NORMAL dependencies only: build scripts, macros' own build deps
        # and dev/test crates do not end up inside the shipped program.
        todo, got = [m["resolve"]["root"]], set()
        while todo:
            i = todo.pop()
            if i in got:
                continue
            got.add(i)
            for d in nodes[i]["deps"]:
                if any(k["kind"] is None for k in d["dep_kinds"]):
                    todo.append(d["pkg"])
        for i in got:
            p = pk[i]
            if p["source"] is None:  # our own code (virus-vigil, the phone plugin)
                continue
            seen[(p["name"], p["version"])] = p
    return [seen[k] for k in sorted(seen)]


def crate_licence_files(p):
    d = Path(p["manifest_path"]).parent
    files = [f for f in sorted(d.iterdir()) if f.is_file() and re.match(r"(?i)(licen[cs]e|copying|notice)", f.name)]
    if p.get("license_file"):
        f = d / p["license_file"]
        if f.exists() and f not in files:
            files.append(f)
    return files


def copyright_of(text):
    m = re.search(r"^\s*(Copyright .+?)\s*$", text, re.M)
    if not m:
        problems.append("no Copyright line in a rule LICENSE")
        return ""
    return m.group(1).rstrip(".")


# ---- write --------------------------------------------------------------------------------------
def main():
    cc = yarahub_cc_by()
    rl, bb, font = rule_licence("rl"), rule_licence("bartblaze"), font_licence()
    cs = crates()
    texts = {}  # hash -> (text, [crate names])
    no_file = []
    for p in cs:
        fs = crate_licence_files(p)
        if not fs:
            no_file.append(p)
        for f in fs:
            t = read(f)
            h = hashlib.sha256(re.sub(r"\s+", " ", t).encode()).hexdigest()
            texts.setdefault(h, (t, []))[1].append(f"{p['name']} {p['version']} ({f.name})")
    if not cs:
        problems.append("no crates found")

    # licenses.txt: every full text once, each headed by who it covers.
    L = ["Virus Vigil - full licence texts of the third-party parts it contains.",
         "Generated by tools/credits.py from the files on disk. The short list is in credits.html.", ""]
    def block(title, body):
        L.extend(["=" * 78, title, "=" * 78, body, ""])
    block("YARA rules by ReversingLabs (src-tauri/yara/rl) - MIT", rl)
    block("YARA rules by bartblaze (src-tauri/yara/bartblaze) - MIT", bb)
    die, lcr = packer_licence("Detect-It-Easy"), packer_licence("LibChecker-Rules")
    block("App-protector file names from Detect It Easy (github.com/horsicq/Detect-It-Easy) - MIT", die)
    block("App-protector file names from LibChecker-Rules (github.com/LibChecker/LibChecker-Rules) and "
          "mHook (github.com/xiamiya/mHook) - Apache License 2.0", lcr)
    block("Atkinson Hyperlegible font (src/fonts) - SIL Open Font License 1.1", font)
    for t, who in sorted(texts.values(), key=lambda v: v[1][0]):
        block("Rust crates: " + "; ".join(who), t)
    if no_file:
        L.append("Crates whose published package carries no licence file (their stated licence applies; the")
        L.append("standard text of that licence appears above under another crate):")
        L.extend(f"  {p['name']} {p['version']} - {p['license']}" for p in no_file)
    (SRC / "licenses.txt").write_text("\n".join(L) + "\n", encoding="utf-8", newline="\n")
    (SRC / "fonts" / "OFL.txt").write_text(font + "\n", encoding="utf-8", newline="\n")

    e = html.escape
    by_lic = {}
    for p in cs:
        by_lic.setdefault(p["license"] or "(not stated)", []).append(f"{p['name']} {p['version']}")
    crate_rows = "".join(f"<tr><td>{e(k)}</td><td>{len(v)}</td><td>{e(', '.join(v))}</td></tr>" for k, v in sorted(by_lic.items()))
    mpl = [p for p in cs if "MPL" in (p["license"] or "")]
    cc_rows = "".join(f"<li><b>{e(n)}</b> by {e(a)} ({e(l)})</li>" for n, l, a in cc)
    ps = packer_sources()
    known = {"die", "lcr", "mhook", "vb2014", "caro2014", "blog", "apkid-fact"}
    if set(ps) - known:
        problems.append(f"PACKERS source tags this page does not credit: {sorted(set(ps) - known)}")
    page = PAGE.format(
        p_total=sum(ps.values()), p_die=ps.get("die", 0), p_lcr=ps.get("lcr", 0), p_mhook=ps.get("mhook", 0),
        p_pub=ps.get("vb2014", 0) + ps.get("caro2014", 0) + ps.get("blog", 0), p_apkid=ps.get("apkid-fact", 0),
        die_copy=e(copyright_of(die)),
        rl_copy=e(copyright_of(rl)), bb_copy=e(copyright_of(bb)),
        cc_rows=cc_rows, n_cc=len(cc), crate_rows=crate_rows, n_crates=len(cs),
        mpl=", ".join(f"{e(p['name'])} {e(p['version'])}" for p in mpl) or "none",
    )
    (SRC / "credits.html").write_text(page, encoding="utf-8", newline="\n")
    print(f"crates {len(cs)}, distinct licence texts {len(texts)}, crates with no licence file {len(no_file)}, "
          f"CC BY rules {len(cc)}, MPL crates {len(mpl)}; licenses.txt {os.path.getsize(SRC / 'licenses.txt'):,} bytes")
    for x in problems:
        print("PROBLEM:", x)
    sys.exit(1 if problems else 0)


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Licences and credits</title>
<!-- Generated by tools/credits.py - edit that, not this. -->
<link rel="stylesheet" href="legal.css">
</head>
<body><main>
<h1>Licences and credits</h1>
<p class="soft">Virus Vigil stands on the work of people who share their research for free. Thank you to every one of them.
The full licence texts are in <a href="licenses.txt">licenses.txt</a>.</p>
<p>Virus Vigil itself: Copyright (c) 2026 Arnav Agarwal. Free under the PolyForm Noncommercial License 1.0.0 - <a href="polyform-noncommercial-1.0.0.txt">read the full licence</a>. The work credited below keeps its own licence.</p>

<h2>Malware knowledge inside the app</h2>
<ul>
<li><b>ReversingLabs YARA rules</b> - github.com/reversinglabs/reversinglabs-yara-rules. MIT licence, {rl_copy}.</li>
<li><b>bartblaze YARA rules</b> - github.com/bartblaze/Yara-rules. MIT licence, {bb_copy}.</li>
<li><b>YARAhub rules</b> from abuse.ch YARAify (yaraify.abuse.ch) - only rules their authors released as CC0 1.0 or CC BY 4.0. The {n_cc} CC BY 4.0 rules, credited to their authors (creativecommons.org/licenses/by/4.0):
<ul>{cc_rows}</ul></li>
<li><b>Stalkerware indicators</b> by Echap (echap.eu.org) and contributors - github.com/AssoEchap/stalkerware-indicators, CC BY 4.0. Used to recognise spy apps.</li>
<li><b>App-protector file names</b> ({p_total} names of files that app-protection tools leave inside apps):
<ul><li>{p_die} from <b>Detect It Easy</b> by horsicq, DosX and contributors - github.com/horsicq/Detect-It-Easy, MIT licence, {die_copy}.</li>
<li>{p_lcr} from <b>LibChecker-Rules</b> by the LibChecker contributors - github.com/LibChecker/LibChecker-Rules, Apache License 2.0.</li>
<li>{p_mhook} from <b>mHook</b> by xiamiya - github.com/xiamiya/mHook, Apache License 2.0.</li>
<li>{p_pub} from published research: Yu, "Android packers: facing challenges, building solutions" (Virus Bulletin 2014); Apvrille and Nigam, Fortinet (CARO 2014); and a 2017 survey of Android packer features (CSDN / Tencent Cloud).</li>
<li>{p_apkid} first noted in <b>APKiD</b> by RedNaga - github.com/rednaga/APKiD. Only the bare file names are used, none of its rules.</li></ul></li>
</ul>

<h2>Lists and services the app asks</h2>
<ul>
<li><b>MalwareBazaar</b> by abuse.ch (bazaar.abuse.ch) - the list of known malware fingerprints.</li>
<li><b>CIRCL hashlookup</b> (hashlookup.circl.lu), Computer Incident Response Center Luxembourg - asked about a file's fingerprint only, never the file.</li>
<li><b>Phishing.Database</b> by Mitchell Krog and contributors - github.com/Phishing-Database/Phishing.Database, MIT licence.</li>
<li><b>Warning List</b> by CERT Polska (NASK-PIB) - hole.cert.pl, a list of phishing sites; its data policy lets anyone use it for any purpose. CERT Polska does not endorse or work with Virus Vigil.</li>
<li><b>chrome-mal-ids</b> by The Privacy Commons Institute - known harmful browser extensions, CC BY 4.0.</li>
<li><b>Pwned Passwords</b> by Have I Been Pwned (haveibeenpwned.com) - only the first 5 characters of a password's hash leave the device.</li>
<li><b>Groq</b> (groq.com) - the optional online helper, only when you choose to send a question.</li>
</ul>
<p class="soft">These organisations provide their data free and "as is", and are not connected with Virus Vigil. They do not endorse it.</p>

<h2>Software the app is built with</h2>
<ul>
<li><b>YARA-X</b> by VirusTotal - BSD 3-Clause licence, Copyright (c) 2024 The YARA-X Authors.</li>
<li><b>Tauri</b> - MIT or Apache 2.0. <b>Android Jetpack (AndroidX) and Material Components</b> by Google - Apache 2.0.</li>
<li><b>Atkinson Hyperlegible</b> font, Copyright 2020 Braille Institute of America, Inc. - SIL Open Font License 1.1 (fonts/OFL.txt).</li>
<li><b>{n_crates} Rust libraries</b>, by licence below. The ones under the Mozilla Public License 2.0 ({mpl}) are used unchanged; their source is at crates.io.</li>
</ul>
<table><tr><th>Licence</th><th>How many</th><th>Libraries</th></tr>{crate_rows}</table>
</main></body>
</html>
"""

if __name__ == "__main__":
    main()
