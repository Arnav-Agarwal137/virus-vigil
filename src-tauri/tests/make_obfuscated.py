"""Make an 'obfuscated' copy of a fixture: the attribute names "name" and "permission"
in the manifest's string pool are overwritten with same-length junk, as obfuscators do.
Android itself identifies attributes by resource id, so the app still works - and a
reader that matches attribute NAMES by text goes blind. Verify the result with aapt.

usage: python make_obfuscated.py <in.apk> <out.apk>
"""
import sys
import zipfile

src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as z:
    axml = bytearray(z.read("AndroidManifest.xml"))

hits = 0
for word, junk in (("name", "qqqq"), ("permission", "qqqqqqqqqq")):
    n = len(word)
    for enc_old, enc_new in (
        (bytes([n, 0]) + word.encode("utf-16-le") + b"\x00\x00", bytes([n, 0]) + junk.encode("utf-16-le") + b"\x00\x00"),
        (bytes([n, n]) + word.encode() + b"\x00", bytes([n, n]) + junk.encode() + b"\x00"),
    ):
        c = axml.count(enc_old)
        hits += c
        axml[:] = axml.replace(enc_old, enc_new)
assert hits >= 2, f"expected to blank both attribute names, blanked {hits}"
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("AndroidManifest.xml", bytes(axml))
print(f"blanked {hits} pool entries -> {dst}")
