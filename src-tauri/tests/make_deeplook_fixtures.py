"""Build the app-file fixtures for deeplook.rs with Android's own aapt2 (29 Sep 2026).

Each is an APK with NO CODE (hasCode=false): it cannot do anything, even installed. Only its
manifest differs:
  vv-hidden-stealer.apk  reads SMS + offers an accessibility service + NO launcher icon
  vv-visible-sms.apk     the same asks, but it shows an icon (like an automation app)
  vv-plain.apk           internet only, shows an icon (an ordinary app)
  vv-hidden-sms.apk      reads SMS, NO launcher icon, no screen control
  vv-visible-smsonly.apk reads SMS, shows an icon (an ordinary SMS app)
  vv-hidden-installer / vv-visible-dropper / vv-hidden-caninstall / vv-visible-caninstall (droppers)
  vv-stalker-placeholder.apk, vv-signed-v1.apk, vv-signed-v2.apk (+ vv-signed.sha1.txt)

usage: python tests/make_deeplook_fixtures.py   (from src-tauri/)
"""
import os, subprocess, tempfile

SDK = "D:/dev/android-sdk"
AAPT2 = f"{SDK}/build-tools/36.0.0/aapt2.exe"
JAR = f"{SDK}/platforms/android-36/android.jar"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

LAUNCHER = """<activity android:name="{pkg}.Main" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>"""
STEALS = """<service android:name="{pkg}.Helper" android:exported="true"
             android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
      <intent-filter><action android:name="android.accessibilityservice.AccessibilityService"/></intent-filter>
    </service>
    <receiver android:name="{pkg}.SmsIn" android:exported="true" android:permission="android.permission.BROADCAST_SMS">
      <intent-filter><action android:name="android.provider.Telephony.SMS_RECEIVED"/></intent-filter>
    </receiver>"""
SMS_PERMS = """<uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <uses-permission android:name="android.permission.READ_SMS"/>"""


def build(name, pkg, perms, body):
    m = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{pkg}">
  {perms}
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:label="Test" android:hasCode="false">
    {body.format(pkg=pkg)}
  </application>
</manifest>
"""
    d = tempfile.mkdtemp()
    mp = os.path.join(d, "AndroidManifest.xml")
    open(mp, "w").write(m)
    out = os.path.join(OUT, name)
    r = subprocess.run([AAPT2, "link", "-o", out, "-I", JAR, "--manifest", mp, "--min-sdk-version", "24",
                        "--target-sdk-version", "34"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    os.remove(mp); os.rmdir(d)
    print(name, os.path.getsize(out))


build("vv-hidden-stealer.apk", "com.whatsapp.update", SMS_PERMS, STEALS)
build("vv-visible-sms.apk", "com.example.automate", SMS_PERMS, STEALS + "\n    " + LAUNCHER)
build("vv-plain.apk", "com.example.plain", "", LAUNCHER)
# 29 Sep (mutants): the hidden rule needs "no icon"; SMS with an icon and no screen control is quiet.
build("vv-hidden-sms.apk", "com.example.hiddensms", SMS_PERMS, "")
build("vv-visible-smsonly.apk", "com.example.smsapp", SMS_PERMS, LAUNCHER)
# 29 Sep evening (the 7 hard gaps): droppers, a stalkerware stand-in, signed apps.
INSTALL = """<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>"""
build("vv-hidden-installer.apk", "com.example.hiddeninst", INSTALL + "\n  " + SMS_PERMS, "")
build("vv-visible-dropper.apk", "com.example.dropper", INSTALL + "\n  " + SMS_PERMS, LAUNCHER)
build("vv-hidden-caninstall.apk", "com.example.caninst", INSTALL, "")
build("vv-visible-caninstall.apk", "com.example.store", INSTALL, LAUNCHER)
# The package is a 21-letter placeholder; the test swaps in a real listed stalkerware package of
# the same length IN MEMORY, so no stalkerware name is ever stored on this disk (the sweep would
# read it).
build("vv-stalker-placeholder.apk", "com.vvtest.placeholdr", "", LAUNCHER)

# Signed copies of vv-plain.apk with a throwaway key (made here, deleted after): one with only the
# v2/v3 signing block, one with only the v1 META-INF signature, so each reader is tested alone.
# The expected SHA-1 is what apksigner itself prints, saved beside them.
BT = f"{SDK}/build-tools/36.0.0"
KEYTOOL = "C:/Program Files/Java/jdk-21/bin/keytool.exe"
d = tempfile.mkdtemp()
ks = os.path.join(d, "t.jks")
subprocess.run([KEYTOOL, "-genkeypair", "-keystore", ks, "-storepass", "vvtest", "-keypass", "vvtest", "-alias", "t",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "36500", "-dname", "CN=Vigil Test"],
               check=True, capture_output=True)
plain = os.path.join(OUT, "vv-plain.apk")
for name, flags in [("vv-signed-v2.apk", ["--v1-signing-enabled", "false", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true"]),
                    ("vv-signed-v1.apk", ["--v1-signing-enabled", "true", "--v2-signing-enabled", "false", "--v3-signing-enabled", "false"])]:
    out = os.path.join(OUT, name)
    subprocess.run(["cmd", "/c", f"{BT}/apksigner.bat", "sign", "--ks", ks, "--ks-pass", "pass:vvtest", *flags,
                    "--out", out, plain], check=True, capture_output=True)
    print(name, os.path.getsize(out))
r = subprocess.run(["cmd", "/c", f"{BT}/apksigner.bat", "verify", "--print-certs", os.path.join(OUT, "vv-signed-v2.apk")],
                   check=True, capture_output=True, text=True)
sha1 = [l.split(":", 1)[1].strip() for l in r.stdout.splitlines() if "certificate SHA-1 digest" in l]
assert len(sha1) == 1, r.stdout
open(os.path.join(OUT, "vv-signed.sha1.txt"), "w").write(sha1[0].upper() + "\n")
print("sha1", sha1[0])
for f in os.listdir(d):
    os.remove(os.path.join(d, f))
os.rmdir(d)
for f in os.listdir(OUT):
    if f.endswith(".idsig"):
        os.remove(os.path.join(OUT, f))
