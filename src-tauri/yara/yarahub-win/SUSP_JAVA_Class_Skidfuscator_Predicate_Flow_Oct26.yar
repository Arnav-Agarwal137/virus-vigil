rule SUSP_JAVA_Class_Skidfuscator_Predicate_Flow_Oct26 : java obfuscation class {
   meta:
      description = "Detects Java class files obfuscated with Skidfuscator based on its opaque predicate seed chain (ldc/ldc_w int; iload p; ixor; istore p) and seed mixing (ixor; ixor; istore)"
      author = "rc4"
      reference = "https://github.com/skidfuscatordev/skidfuscator-java-obfuscator"
      date = "2026-10-02"
      id = "694dbaf1-57d1-5e4e-8d89-d7b4f097e909"
      modified = "2026-10-07"
      license = "CC-BY-4.0"
      category = "obfuscator"
      scope = "class"
      confidence = "moderate"
      hash1 = "b1e24760fccaf5dda7409a7b7a06247eec41a93e26a9d842233f68b948227cf0"
      yarahub_uuid = "0c6267ba-3515-4d32-8d9d-98afa315ec69"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "50b7ba9e7ea3257cf465691e576dbe44"
   strings:
      $mix1 = { 82 82 36 ?? }                       /* ixor ; ixor ; istore p */
      $mix2 = { 82 82 C4 36 ?? ?? }                 /* ixor ; ixor ; wide istore p */
      $upd1 = { 12 ?? 15 ?? 82 36 ?? }              /* ldc ; iload p ; ixor ; istore p */
      $upd2 = { 13 ?? ?? 15 ?? 82 36 ?? }           /* ldc_w ; ... */
      $upd3 = { 12 ?? C4 15 ?? ?? 82 C4 36 ?? ?? }  /* ldc ; wide iload ; ixor ; wide istore */
      $upd4 = { 13 ?? ?? C4 15 ?? ?? 82 C4 36 ?? ?? } /* ldc_w ; wide iload ; ixor ; wide istore */
   condition:
      uint32be(0) == 0xCAFEBABE
      and uint16be(6) >= 45 and uint16be(6) <= 80
      and filesize < 16MB
      and 1 of ($mix*)
      and (#upd1 + #upd2 + #upd3 + #upd4) >= 2
}
