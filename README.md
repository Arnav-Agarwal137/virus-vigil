# Virus Vigil

A malware, spy-app and scam checker that explains what it finds in plain words. It runs on the device it is checking:

- **Laptop (Windows 10/11)** - checks files and folders against known malware fingerprints and YARA rules, looks for
  spy and remote-control software, reads the security settings that matter (Defender, firewall, SmartScreen, account
  control and more) and, only after you approve each change, can switch the weak ones to safe values. Every change it
  makes can be undone from the app.
- **Phone (Android 7 or newer)** - checks every installed app against known malware and spy-app lists, checks files in
  your storage, and walks you through the fixes Android lets an app start (the app opens the right Settings page or
  Android's own Uninstall box; you make the tap).

**What leaves your device:** a file's fingerprint (never the file), the first 5 characters of a password's hash when
you ask about a password, a question you choose to send to the optional online helper, and plain list downloads. The
full list, with who receives each one and why: [PRIVACY.md](PRIVACY.md).

**No security tool catches everything.** A clean result means nothing was found in what was checked; it does not mean
the device is safe. See [DISCLAIMER.md](DISCLAIMER.md).

## Licence

Copyright (c) 2026 Arnav Agarwal. Released under the **PolyForm Noncommercial License 1.0.0** ([LICENSE](LICENSE)).

In plain words: you may use it, change it and share it, free, for any **non-commercial** purpose. Selling it, putting
it inside something you sell, or using it to earn money needs a separate licence from the owner - see
[COMMERCIAL.md](COMMERCIAL.md).

This is a "source-available" licence, not an OSI "open source" licence, so app stores that list only open-source apps
(for example F-Droid) will not list it.

The malware rules, lists and libraries inside the app belong to their authors and keep their own licences; see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Build

The app is built with [Tauri 2](https://tauri.app) (Rust + a web page). You need Rust, Node.js and, for the phone,
JDK 21, the Android SDK and NDK.

```
npm install
npm run tauri build                          # Windows installer
bash build-android.sh aarch64 release        # Android APK
```

`build-android.sh` reads `ANDROID_HOME`, `NDK_HOME` and `JAVA_HOME` from your environment. A release APK is signed
only with your own signing file; **no signing key is included in this repository.**

**The optional online helper needs a Groq API key, and none is included.** Without one the helper says it is not set
up and everything else works. On a laptop, set the environment variable `GROQ_API_KEY` before starting the app. Do
not bake your own key into a build you give to other people: anyone holding the file can pull it out.

## Tests

```
cd src-tauri && cargo test          # Rust checks
cd tests/page && bash run.sh *.mjs  # page checks in a headless Chrome; always name the suites
```

Some Rust tests read sample APK files that are **not included** (they are built apps, and one is another project's
GPL-3 app). `src-tauri/tests/make_deeplook_fixtures.py` (run from `src-tauri/`) rebuilds the samples it can; tests whose sample is missing will fail
until you add your own.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Questions, bugs and licence requests: open an issue on GitHub.

Virus Vigil is an independent project. It is not connected to, endorsed by or affiliated with Microsoft, Google,
abuse.ch, CIRCL, Have I Been Pwned, Groq or any antivirus maker. Product names mentioned belong to their owners.
