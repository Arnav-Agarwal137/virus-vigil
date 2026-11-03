rule SUSP_JAVA_JAR_Skidfuscator_Random_Runtime_Path_Oct26 : java obfuscation jar {
   meta:
      description = "Detects JAR files containing a class at a randomized 16+16 lowercase letter path as used for the runtime class of Skidfuscator 2.0.x community builds (heuristic, lower confidence)"
      author = "rc4"
      reference = "https://github.com/skidfuscatordev/skidfuscator-java-obfuscator"
      date = "2026-10-02"
      id = "25ca4ab4-b866-5403-b948-2fc219475cef"
      modified = "2026-10-07"
      license = "CC-BY-4.0"
      category = "obfuscator"
      scope = "jar"
      confidence = "moderate"
      hash1 = "f0aa95e0c712a1cc9a8733562b0a59bb907bbda06cdb896d42b3c4f4f01537ea"
      yarahub_uuid = "a038820c-0230-4bcc-b14a-65a1a472d53f"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "977451ce759112925bb90a824c8879d6"
      yarahub_reference_link = "https://github.com/skidfuscatordev/skidfuscator-java-obfuscator"
   strings:
      $r1 = /[a-z]{16}\/[a-z]{16}\.class/
   condition:
      uint32(0) == 0x04034B50 and filesize < 100MB
      and for any i in (1..#r1) : (
         @r1[i] >= 46
         and uint32(@r1[i] - 46) == 0x02014B50
         and uint16(@r1[i] - 18) == 39
      )
}
