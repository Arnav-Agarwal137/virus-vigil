"""Build the small test fixtures for the APK reader and print the expected answers.

Independent of the Rust code on purpose: the Rust side finds permissions with a regex
over the raw bytes; this script walks the binary-XML string pool properly, so the two
disagreeing would mean one of them is wrong.

usage: python make_fixtures.py <real.apk> <out_dir> <name>
"""
import json
import struct
import sys
import zipfile
from pathlib import Path


def string_pool(axml: bytes) -> list[str]:
    # ResXMLTree header (8 bytes), then the ResStringPool chunk.
    typ, hsize, size = struct.unpack_from("<HHI", axml, 8)
    assert typ == 0x0001, f"expected string pool chunk, got {typ:#x}"
    count, _styles, flags, str_start, _sty_start = struct.unpack_from("<IIIII", axml, 16)
    utf8 = bool(flags & (1 << 8))
    offsets = struct.unpack_from(f"<{count}I", axml, 8 + hsize)
    base = 8 + str_start
    out = []
    for off in offsets:
        p = base + off
        if utf8:
            n = axml[p]; p += 2 if n & 0x80 else 1           # utf-16 length (skip)
            n = axml[p]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | axml[p + 1]; p += 2
            else:
                p += 1
            out.append(axml[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", axml, p)[0]; p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", axml, p)[0]; p += 2
            out.append(axml[p:p + 2 * n].decode("utf-16-le", "replace"))
    return out


def main() -> None:
    apk, out_dir, name = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk) as z:
        axml = z.read("AndroidManifest.xml")
    perms = sorted({s for s in string_pool(axml) if s.startswith("android.permission.")})
    small = out_dir / f"{name}.apk"
    with zipfile.ZipFile(small, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", axml)
    (out_dir / f"{name}.expected.json").write_text(json.dumps(perms, indent=1) + "\n", encoding="utf-8")
    print(f"{name}: {len(perms)} permissions, fixture {small.stat().st_size} bytes")


if __name__ == "__main__":
    main()
