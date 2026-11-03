rule SUSP_JAVA_Class_SB27_String_Encryption_Oct26 : java obfuscation class {
   meta:
      description = "Detects Java class files obfuscated with the superblaubeere27 (sb27/JObf) obfuscator based on its (String,String)String decryptors using DES, Blowfish or AES with MD5/SHA-256 derived keys, corroborated by number obfuscation or the XOR decryptor template"
      author = "rc4"
      reference = "https://github.com/superblaubeere27/obfuscator"
      date = "2026-10-02"
      id = "29780016-87c5-51ab-ba6d-d4d57ad2f146"
      modified = "2026-10-07"
      license = "CC-BY-4.0"
      category = "obfuscator"
      scope = "class"
      confidence = "high"
      hash1 = "c82e35588702d43f9f576cc6f3fca32b011bef8545adfcf9a137023891d7796e"
      yarahub_uuid = "937f8bb0-1757-44ee-8a07-e867c27b185e"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "d82cfd0c2bc59e432ee9fa47f174b139"
      yarahub_reference_link = "https://github.com/superblaubeere27/obfuscator"
   strings:
      $s1 = "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" ascii
      $s2 = "javax/crypto/Cipher" ascii
      $s3 = "javax/crypto/spec/SecretKeySpec" ascii
      $s4 = "java/util/Base64$Decoder" ascii

      $h1 = { 01 00 03 4D 44 35 }                       /* Utf8 "MD5" */
      $h2 = { 01 00 07 53 48 41 2D 32 35 36 }           /* Utf8 "SHA-256" */

      $n1 = { ( 10 ?? | 11 ?? ?? | 12 ?? | 04 | 05 | 06 | 07 | 08 ) BC 0A B3 ?? ?? B2 ?? ?? 03 [1-24] ( 60 | 64 | 68 | 74 | 7E | 80 | 82 ) }
      $n2 = { ( 10 ?? | 11 ?? ?? | 12 ?? | 04 | 05 | 06 | 07 | 08 ) BC 0A B3 ?? ?? B2 ?? ?? 03 ( 12 ?? | 13 ?? ?? ) B6 ?? ?? }

      $c1 = { 01 00 03 44 45 53 }                       /* Utf8 "DES" */
      $c2 = { 01 00 08 42 6C 6F 77 66 69 73 68 }        /* Utf8 "Blowfish" */
      $c3 = { 01 00 03 41 45 53 }                       /* Utf8 "AES" */
      $xor_setup = { BB ?? ?? 59 B8 ?? ?? 2A B2 ?? ?? B6 ?? ?? B6 ?? ?? B2 ?? ?? B7 ?? ?? 4B }
      $xor_loop = { 2D 15 ?? 2D BE 70 34 82 92 B6 ?? ?? }
   condition:
      uint32be(0) == 0xCAFEBABE
      and uint16be(6) >= 45 and uint16be(6) <= 80
      and filesize < 16MB
      and all of ($s*)
      and 1 of ($h*)
      and 1 of ($c*)
      and (1 of ($n*) or all of ($xor*))
}
