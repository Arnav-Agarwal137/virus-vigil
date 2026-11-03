import "pe"

rule RWX_S_Signed_Search
{
	meta:
		description = "rwx-s binaries"
		author = "Bill Demirkapi"
		reference = "https://billdemirkapi.me/sharing-is-caring-abusing-shared-sections-for-code-injection/"
		date = "2026-10-02"
		yarahub_uuid = "5040ff31-2a3f-48c8-a7f4-983a0a8ddd73"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:RED"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "6266157ad7f222c704d45769485a939c"
	condition:
		pe.is_pe and
		for any i in (0..pe.number_of_sections - 1): (
			(pe.sections[i].characteristics & pe.SECTION_MEM_READ) and
			(pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) and
			(pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) and
			(pe.sections[i].characteristics & pe.SECTION_MEM_SHARED) )
		and pe.number_of_signatures > 0
}
