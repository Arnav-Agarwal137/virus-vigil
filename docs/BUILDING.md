# Build and maintenance guide

Run these commands from the repository root.

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

See [CONTRIBUTING.md](../CONTRIBUTING.md). Questions, bugs and licence requests: open an issue on GitHub.

Virus Vigil is an independent project. It is not connected to, endorsed by or affiliated with Microsoft, Google,
abuse.ch, CIRCL, Have I Been Pwned, Groq or any antivirus maker. Product names mentioned belong to their owners.
