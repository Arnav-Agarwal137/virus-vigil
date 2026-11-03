rule SUSP_JAVA_Class_SB27_String_Encryption_XOR_Oct26 : java obfuscation class {
   meta:
      description = "Detects Java class files obfuscated with the superblaubeere27 (sb27/JObf) obfuscator based on its XOR string decryptor template (Base64 decode, cyclic key XOR)"
      author = "rc4"
      reference = "https://github.com/superblaubeere27/obfuscator"
      date = "2026-10-02"
      id = "52888bf3-3527-5cb0-aa1a-f15d577c6a5b"
      modified = "2026-10-07"
      license = "CC-BY-4.0"
      category = "obfuscator"
      scope = "class"
      confidence = "high"
      hash1 = "c82e35588702d43f9f576cc6f3fca32b011bef8545adfcf9a137023891d7796e"
      yarahub_uuid = "9a73aae3-2ff2-454a-87eb-7d337daa326f"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "d82cfd0c2bc59e432ee9fa47f174b139"
      yarahub_reference_link = "https://github.com/superblaubeere27/obfuscator"
   strings:
      $s1 = "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" ascii
      $op1 = { BB ?? ?? 59 B8 ?? ?? 2A B2 ?? ?? B6 ?? ?? B6 ?? ?? B2 ?? ?? B7 ?? ?? 4B }
      $op2 = { 2D 15 ?? 2D BE 70 34 82 92 B6 ?? ?? }
   condition:
      uint32be(0) == 0xCAFEBABE
      and uint16be(6) >= 45 and uint16be(6) <= 80
      and filesize < 16MB
      and all of them
}
