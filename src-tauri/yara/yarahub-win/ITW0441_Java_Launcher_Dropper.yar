import "pe"
import "math"
rule ITW0441_Java_Launcher_Dropper {
    meta:
        description = "Campagne InTheWild.0441 : lanceur Java Oracle (jli, .text 3.5K) + overlay compresse/chiffre 70K-500K"
        author = "Marjoriefort"
        confidence = "medium"
        date = "2026-09-25"
        yarahub_uuid = "b8f878d0-fc9d-4973-9147-05209ecc7f46"
        reference = "audit ITW.0441 2026-09-25"
        yarahub_reference_md5 = "3ca5f92f3676c3c83f2514ce77476e17"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $jli1 = "JLI_GetStdArgs" ascii
        $jli2 = "JLI_Launch" ascii
    condition:
        uint16(0) == 0x5A4D and pe.is_pe
        and pe.characteristics & pe.EXECUTABLE_IMAGE
        and for any i in (0..pe.number_of_sections-1): (
            pe.sections[i].name == ".text" and pe.sections[i].raw_data_size <= 0x4000 )
        and pe.overlay.size >= 40000
        and math.entropy(pe.overlay.offset, pe.overlay.size) >= 5.8
        and math.entropy(pe.overlay.offset, pe.overlay.size) <= 7.9
        and ($jli1 or $jli2)
}
