rule MULTI_Sample_Unique_e4536a0b
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "e4536a0b2d78966478338e1a176475ee75081eeb7d01fc204e0dbc12584de6c6"
        yarahub_uuid = "e651a561-3cbe-4857-8e5a-a9ce9fd1af3c"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "86e83533f596f73bebdec64dbe4d049f"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "# Gson ProGuard and R8 rules which are relevant for all users" ascii
        $s1 = "# - These rules are additive; don't include anything here which is not specific to Gson (such as completely" ascii
        $s2 = "# - These rules are not complete; users will most likely have to add additional rules for their specific" ascii
        $s3 = "#   classes, for example to disable obfuscation for certain fields or to keep no-args constructors" ascii
        $s4 = "Note: Cannot perform finer selection here to only cover Gson annotations, see also https://stackoverflow.com/q/47515093" ascii
        $s5 = "# The following rules are needed for R8 in \"full mode\" which only adheres to `-keepattribtues` if" ascii
        $s6 = "# the corresponding class or field is matches by a `-keep` rule as well, see" ascii
        $s7 = "# https://r8.googlesource.com/r8/+/refs/heads/main/compatibility-faq.md#r8-full-mode" ascii
        $s8 = "if class com.google.gson.reflect.TypeToken" ascii
        $s9 = "keep,allowobfuscation class com.google.gson.reflect.TypeToken" ascii
        $s10 = "keep,allowobfuscation class * extends com.google.gson.reflect.TypeToken" ascii
        $s11 = "keep,allowobfuscation,allowoptimization @com.google.gson.annotations.JsonAdapter class *" ascii
        $s12 = "@com.google.gson.annotations.Expose <fields>;" ascii
        $s13 = "@com.google.gson.annotations.JsonAdapter <fields>;" ascii
        $s14 = "@com.google.gson.annotations.Since <fields>;" ascii
        $s15 = "@com.google.gson.annotations.Until <fields>;" ascii
        $s16 = "Keep no-args constructor of classes which can be used with @JsonAdapter" ascii
        $s17 = "By default their no-args constructor is invoked to create an adapter instance" ascii
        $s18 = "keepclassmembers class * extends com.google.gson.TypeAdapter {" ascii
        $s19 = "keepclassmembers class * implements com.google.gson.TypeAdapterFactory {" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s1, $s2, $s3, $s5, $s6, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19) and 1 of ($s4, $s7)
}
