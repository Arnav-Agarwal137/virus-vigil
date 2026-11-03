# Builds prefetch fixtures for deep.ps1's test (no admin needed to read these).
# Layout follows the Windows 10/11 format: "MAM\x04" + uncompressed size + Xpress-Huffman data,
# compressed here by Windows' own ntdll (RtlCompressBuffer, format 4). Inside: an SCCA v30 header
# with the program name at offset 16, and the recorded paths as NUL-separated UTF-16 strings.
# LIMIT: these are built from the format notes, not taken from a real machine (Prefetch needs admin).
# The first real deep check on the owner's laptop is what proves the parser on real files.
import ctypes, os, struct, sys

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prefetch")
ntdll = ctypes.WinDLL("ntdll")

def compress(data: bytes) -> bytes:
    fmt = 4 | 0x0100  # XPRESS_HUFF | COMPRESSION_ENGINE_MAXIMUM
    ws_buf, ws_frag = ctypes.c_ulong(), ctypes.c_ulong()
    assert ntdll.RtlGetCompressionWorkSpaceSize(fmt, ctypes.byref(ws_buf), ctypes.byref(ws_frag)) == 0
    ws = ctypes.create_string_buffer(ws_buf.value)
    out = ctypes.create_string_buffer(len(data) + 4096)
    final = ctypes.c_ulong()
    st = ntdll.RtlCompressBuffer(fmt, data, len(data), out, len(out), 4096, ctypes.byref(final), ws)
    assert st == 0, hex(st & 0xFFFFFFFF)
    return out.raw[: final.value]

def scca(exe: str, paths, odd=False) -> bytes:
    head = bytearray(0x100)
    struct.pack_into("<I4s", head, 0, 30, b"SCCA")
    name = exe.encode("utf-16-le")[:58]
    head[16 : 16 + len(name)] = name
    pad = b"\x00" if odd else b""  # puts the strings block on an odd byte offset
    body = b"".join(p.encode("utf-16-le") + b"\x00\x00" for p in paths)
    data = bytes(head) + pad + body
    struct.pack_into("<I", data := bytearray(data), 12, len(data))
    return bytes(data)

def mam(raw: bytes) -> bytes:
    return b"MAM\x04" + struct.pack("<I", len(raw)) + compress(raw)

V = r"\VOLUME{01dc2c3e8a1b2c3d-4e5f6071}"
CASES = {
    # the 12 Sep shape: a "free game" installer run straight out of Downloads
    "SETUP.EXE-1A2B3C4D.pf": mam(scca("SETUP.EXE", [V + r"\WINDOWS\SYSTEM32\NTDLL.DLL", V + r"\USERS\TESTER\DOWNLOADS\FREEGAME\SETUP.EXE", V + r"\WINDOWS\SYSTEM32\KERNEL32.DLL"])),
    # run from inside a zip Explorer opened
    "INSTALL.EXE-22222222.pf": mam(scca("INSTALL.EXE", [V + r"\USERS\TESTER\APPDATA\LOCAL\TEMP\TEMP1_CRACK.ZIP\INSTALL.EXE"], odd=True)),
    # normal: an installer unpacking itself to Temp, and a program in Program Files
    "CHROME_INSTALLER.EXE-33333333.pf": mam(scca("CHROME_INSTALLER.EXE", [V + r"\USERS\TESTER\APPDATA\LOCAL\TEMP\CR_1234.TMP\CHROME_INSTALLER.EXE"])),
    "NOTEPAD.EXE-44444444.pf": mam(scca("NOTEPAD.EXE", [r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\NOTEPAD.EXE"])),
    # a DLL named like the program in Downloads must not be mistaken for the program's own path
    "TOOL.EXE-55555555.pf": mam(scca("TOOL.EXE", [V + r"\USERS\TESTER\DOWNLOADS\TOOL.EXE.DLL", V + r"\PROGRAM FILES\TOOL\TOOL.EXE"])),
    # an old uncompressed file (Windows 8 and before) run from WinRAR's temp folder
    "OLD.EXE-66666666.pf": scca("OLD.EXE", [r"\DEVICE\HARDDISKVOLUME2\USERS\TESTER\APPDATA\LOCAL\TEMP\RAR$EXA1234.5678\OLD.EXE"]),
    # damaged: must be counted as unread, never break the run
    "BROKEN.EXE-77777777.pf": b"MAM\x04" + struct.pack("<I", 5000) + b"\x13\x37" * 40,
}

if __name__ == "__main__":
    os.makedirs(HERE, exist_ok=True)
    for n, b in CASES.items():
        open(os.path.join(HERE, n), "wb").write(b)
    print(len(CASES), "files in", HERE)
