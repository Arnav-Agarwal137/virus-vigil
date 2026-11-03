import "pe"

rule BubbleGym_Loader_Win64
{
    meta:
        description = "BubbleGym loader (win.bubblegym; supersedes FakeTorrent_Loader_HashedAPI_Win64, yarahub uuid 266eae0e-9afd-4373-a3d3-7ff6d5709824). Stage-1 x64 loader from fake TV-episode torrents (LimeTorrents etc., Oct 2026; same campaign as Thereallo's South Park S29E03 analysis, C2 beenetprotect.com). Decoy USER32/GDI32/ole32 imports with no kernel32, a \\SystemRoot\\System32\\ native path, and repeated FNV-1a prime multiplications (the article documents FNV-1a for the footer; its role in API resolution is unverified). Per that analysis the overlay carries a ChaCha20-encrypted stealer and a 64-byte footer, behind roughly 0.9-1 GB of padding."
        author = "PeterFellow"
        family = "BubbleGym"
        date = "2026-10-23"
        modified = "2026-10-23"
        reference = "https://bazaar.abuse.ch/sample/8ce1805f5b1ca8c4ecd4d1731caf37de33c52e686200331f4a0ea4e6b31ff606/"
        report = "https://github.com/PeterFellow/bubblegym"
        hash1 = "8ce1805f5b1ca8c4ecd4d1731caf37de33c52e686200331f4a0ea4e6b31ff606"
        hash2 = "58dffd262bb9b3c815f1017735cfa214fbbb029af8bd4cbba42c3d8db218e582"
        yarahub_uuid = "d3865ae0-0244-4e3f-ac30-8988634e442f"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "50676b460438904645e30674d438f6af"

    strings:
        $sysroot = "\\SystemRoot\\System32\\" wide
        // imul r32, r/m32, 0x01000193 (FNV-1a prime); 61-77 occurrences in known builds
        $fnv = { 69 ?? 93 01 00 01 }
        // wide-char ASCII case folding: cmp ax,'A' / jb / cmp ax,'Z'
        $lower = { 66 83 F8 41 72 ?? 66 83 F8 5A }

    condition:
        uint16(0) == 0x5A4D
        and pe.is_64bit()
        and pe.number_of_imports <= 6
        and pe.imports(/kernel32\.dll/i, /.*/) == 0
        and pe.imports("USER32.dll", "GetDesktopWindow")
        and pe.imports("GDI32.dll", "GetDeviceCaps")
        and pe.imports("ole32.dll", "CoInitializeEx")
        and $sysroot
        and #fnv >= 10
        and $lower
}
