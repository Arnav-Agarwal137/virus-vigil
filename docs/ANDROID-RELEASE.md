# Android 0.1.38 release checks

The public APK is the share build made on 5 November 2026, version code 1038,
package `com.arnav.virusvigil`, for ARM64 and Android API 24 or newer.

- Android `apksigner verify` accepts its APK Signature Scheme v2 signature.
  The certificate is issued to Arnav Agarwal / Virus Vigil, uses RSA 4096, and has
  SHA-256 fingerprint `5d7d7b03f9112c56487e8e9b31e2e06d1810087915d47d092328ff18e01faf06`.
- All uncompressed APK entries were checked for the developer's configured Groq
  and abuse.ch key values, Groq key-shaped strings, and private-key blocks. None
  were found. This is a bounded key check, not a general security certification.
- Exact compressed copies of the credits, full third-party licence texts, font
  licence, privacy notice, terms, and PolyForm licence were located in the APK's
  native library and decompressed for inspection.
- The embedded credits report **zero APKiD-only protector names**. The earlier
  documentation claiming eleven was stale. Detection-source licences and
  third-party rights remain separate from this project's own licence.
- The APK contains no private test APK fixtures. Local compiler source paths
  remain in its native library; no user documents or personal API keys are included.

## What the licence means for this APK

This existing build carries PolyForm Noncommercial 1.0.0, not an exclusive new
controlled-distribution grant. Permitted noncommercial use, changes and
redistribution remain available under that licence, with its notices. Selling
or other unpermitted commercial use needs separate permission. The root licence
cannot revoke rights already granted to the same code. See LICENSE-HISTORY.md.

## Limits and online services

This is a development preview, not independently certified antivirus protection.
A clean result is not a guarantee. Keep Android's protections enabled.
No developer service key is supplied: the optional Groq helper and authenticated
MalwareBazaar downloads are not preconfigured. Missing checks must not be read as
clean results. Other online steps may still operate: list downloads, unknown-file
hash lookups with CIRCL, and password-hash-prefix checks with Pwned Passwords.
Their providers see normal request information, including the device's IP address.

abuse.ch's terms limit its authenticated free MalwareBazaar access to eligible
not-for-profit purposes and impose usage limits; commercial access may need a
Spamhaus agreement. CIRCL describes hashlookup as a free best-effort service;
no blanket commercial clearance is claimed. These runtime providers' terms are
not replaced by the app's licence.

The release includes the signed APK, SHA256SUMS.txt, and a separate legal-notices
archive. The same licence and privacy material can also be read inside the app.
