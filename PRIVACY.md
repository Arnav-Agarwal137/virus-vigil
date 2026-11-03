# Privacy policy - Virus Vigil

Effective 9 October 2026. Applies to the Windows app and the Android app published by Arnav Agarwal. The same text is
inside the app (the "Privacy" link at the bottom of the page).

## The short version

**Virus Vigil checks your device on the device itself. It never uploads a file.** There is no account, no sign-in,
no advertising and no analytics or tracking code. The owner of this project runs no server and receives nothing from
the app.

## What stays on your device

- Your files, photos, messages, contacts and app data. The app reads files to check them and never uploads one.
- What it found, the lists it downloaded, and the fingerprints it has already worked out (so it need not repeat the
  work). Uninstalling the app removes everything it stored.

## What leaves your device, and only for these reasons

| What is sent | To whom | Why |
|---|---|---|
| A file's fingerprint (its SHA-256 number). A fingerprint cannot be turned back into the file. Sent only for files none of the app's own lists knew, at most 300 in one check. | CIRCL hashlookup (Luxembourg) | To learn whether malware collections have already reported that file. |
| The first 5 characters of a password's hash, only when you ask whether a password has leaked. The password itself never leaves. | Have I Been Pwned (Pwned Passwords) | To check the password against known leaks without revealing it. |
| A question you type, only when you choose to send it to the online helper. Before sending, the app removes phone, card, account and Aadhaar numbers, codes, e-mail and UPI addresses, links and names, and shows you exactly what will go. | Groq (the online helper; only if a key is set up) | To answer a question the app's own library cannot. |
| A request to download a list. Nothing about you is in it. | abuse.ch MalwareBazaar, GitHub (Phishing.Database, chrome-mal-ids), CERT Polska (hole.cert.pl) | To keep the lists of known malware, scam sites and harmful browser add-ons up to date. |

Like any internet request, each of these shows the receiving service your device's internet (IP) address. Those
services have their own privacy policies. Virus Vigil does not send them your name, your contacts or your files.

## Permissions on a phone

- **All files access** - to read the files in your storage and check them. Read only; the app never changes or deletes
  your files.
- **See installed apps** - to check each app against known malware and spy-app lists.
- **Ask to uninstall apps** - lets an Uninstall button open Android's own Uninstall box for an app the check found.
  Android asks you to confirm; nothing is removed unless you tap OK there.
- **Internet and network state** - only for the uses in the table above, and to avoid the large list download on a
  metered connection.

## Changes on a laptop

The laptop app changes a Windows or browser security setting only after you approve it, and Windows asks you again.
Every change can be undone from the app. It never deletes, moves or uploads your files.

## Your choices

- To stop anything leaving, switch the internet off before checking. The checks that run on the device still work,
  and the app says which online steps it could not do.
- The online helper sends nothing unless you press send.

## Children

The app is not designed for children and is not directed at them.

## Changes and contact

If this policy changes, the new version will be published here with a new date. Questions: open an issue on the
project's GitHub page (github.com/Arnav-Agarwal137).
