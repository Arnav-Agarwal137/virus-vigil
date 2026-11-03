# Third-party notices - Virus Vigil

Virus Vigil itself is Copyright (c) 2026 Arnav Agarwal, PolyForm Noncommercial 1.0.0 (see LICENSE). It uses or works
with the following, each under its own terms. Full licence texts are in `src/licenses.txt` and `src/fonts/OFL.txt`,
and inside the app (the "Licences and credits" link at the bottom of the page), which also names every Rust library.

## Malware knowledge shipped inside the app

| What | Author | Licence |
|---|---|---|
| YARA rules | ReversingLabs (github.com/reversinglabs/reversinglabs-yara-rules) | MIT |
| YARA rules | bartblaze (github.com/bartblaze/Yara-rules) | MIT |
| YARAhub rules | their individual authors, via abuse.ch YARAify | Only rules released as CC0 1.0 or CC BY 4.0; the 5 CC BY 4.0 rules are credited by name in the app |
| Stalkerware indicators | Echap and contributors (github.com/AssoEchap/stalkerware-indicators) | CC BY 4.0 |
| App-protector file names: 84 | Detect It Easy, horsicq, DosX and contributors | MIT |
| App-protector file names: 20 | LibChecker-Rules contributors | Apache License 2.0 |
| App-protector file names: 3 | mHook, xiamiya | Apache License 2.0 |
| App-protector file names: 5 | published research (Virus Bulletin 2014; Fortinet, CARO 2014; a 2017 survey) | facts from publications |
| App-protector file names: 11 | first noted in APKiD by RedNaga | Only the bare file names are used, none of its rules or code |

## Lists and services the app asks (not included; downloaded or asked at run time)

| What | Run by | Terms |
|---|---|---|
| MalwareBazaar known-malware fingerprints | abuse.ch | abuse.ch's terms of use |
| hashlookup (fingerprint look-up) | CIRCL, Luxembourg | CIRCL's terms |
| Pwned Passwords | Have I Been Pwned | CC BY 4.0, k-anonymity API |
| Phishing.Database | Mitchell Krog and contributors | MIT |
| Warning List (phishing domains) | CERT Polska (NASK-PIB) | Data usage policy at cert.pl/en/warning-list: "any purpose, including commercial purposes", no attribution required |
| chrome-mal-ids | The Privacy Commons Institute | CC BY 4.0 |
| Groq API (optional online helper) | Groq | Groq's terms; needs the user's own key |

These organisations provide their data "as is" and are not connected with Virus Vigil. They do not endorse it.

## Software the app is built with

| What | Licence |
|---|---|
| YARA-X, VirusTotal | BSD 3-Clause |
| Tauri | MIT or Apache 2.0 |
| Android Jetpack (AndroidX), Material Components, Google | Apache 2.0 |
| Atkinson Hyperlegible font, Braille Institute of America | SIL Open Font License 1.1 |
| Rust libraries (listed one by one in the app) | mostly MIT / Apache 2.0; also BSD, ISC, Zlib, Unicode-3.0, Unlicense, and five under MPL-2.0 used unchanged (source at crates.io) |

## Not included in this repository

Sample APK files used by some tests are left out: they are built apps, and one is the F-Droid client (GPL-3.0). See
"Tests" in README.md.

If you believe something here is credited wrongly or missing, please open an issue.
