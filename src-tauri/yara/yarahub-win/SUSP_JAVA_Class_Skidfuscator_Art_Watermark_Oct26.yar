rule SUSP_JAVA_Class_Skidfuscator_Art_Watermark_Oct26 : java obfuscation class {
   meta:
      description = "Detects Skidfuscator optional artwork watermark: field marker, String array descriptor, and two known artwork lines"
      reference = "https://github.com/skidfuscatordev/skidfuscator-java-obfuscator/blob/e4c0f981911703e86ac8a2b1a77d7cfd18b9d719/dev.skidfuscator.obfuscator/src/main/java/dev/skidfuscator/obfuscator/transform/impl/misc/AhegaoTransformer.java"
      date = "2026-10-07"
      author = "rc4"
      id = "78df3b29-25b4-537a-8e9e-8a495cd074a6"
      modified = "2026-10-07"
      license = "CC-BY-4.0"
      category = "obfuscator"
      scope = "class"
      confidence = "high"
      hash1 = "b1e24760fccaf5dda7409a7b7a06247eec41a93e26a9d842233f68b948227cf0"
      yarahub_uuid = "d896c490-5e42-43fd-b28b-9f7a7f8377c9"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "50b7ba9e7ea3257cf465691e576dbe44"
      yarahub_reference_link = "https://github.com/skidfuscatordev/skidfuscator-java-obfuscator/blob/e4c0f981911703e86ac8a2b1a77d7cfd18b9d719/dev.skidfuscator.obfuscator/src/main/java/dev/skidfuscator/obfuscator/transform/impl/misc/AhegaoTransformer.java"
   strings:
      $field = "nothing_to_see_here" ascii
      $descriptor = "[Ljava/lang/String;" ascii
      $art0 = {
         E2 A2 B8 E2 A3 BF E2 A3 A6 E2 A3 8C E2 A3 9B E2
         A3 BB E2 A3 BF E2 A3 BF E2 A3 A7 E2 A0 99 E2 A0
         9B E2 A0 9B E2 A1 AD E2 A0 85 E2 A0 92 E2 A0 A6
         E2 A0 AD E2 A3 AD E2 A1 BB E2 A3 BF E2 A3 BF E2
         A3 BF E2 A3 BF E2 A3 BF E2 A3 BF E2 A3 BF E2 A3
         BF E2 A1 BF E2 A0 83 E2 A0 84
      }
      $art1 = {
         E2 A0 84 E2 A2 80 E2 A2 B8 E2 A3 BF E2 A3 B7 E2
         A3 A4 E2 A3 A4 E2 A3 A4 E2 A3 AC E2 A3 99 E2 A3
         9B E2 A2 BF E2 A3 BF E2 A3 BF E2 A3 BF E2 A3 BF
         E2 A3 BF E2 A3 BF E2 A1 BF E2 A3 BF E2 A3 BF E2
         A1 8D E2 A0 84 E2 A0 84 E2 A2 80 E2 A3 A4 E2 A3
         84 E2 A0 89 E2 A0 8B E2 A3 B0
      }
      $art2 = {
         E2 A0 84 E2 A0 84 E2 A0 84 E2 A0 84 E2 A0 84 E2
         A2 B8 E2 A1 9F E2 A3 B7 E2 A2 BF E2 A2 88 E2 A3
         9A E2 A3 93 E2 A1 A1 E2 A3 BB E2 A3 BF E2 A3 B6
         E2 A3 AC E2 A3 9B E2 A3 93 E2 A3 89 E2 A1 BB E2
         A2 BF E2 A3 8E E2 A0 A2 E2 A0 BB E2 A3 B4 E2 A1
         BE E2 A0 AB
      }
      $art3 = {
         E2 A2 B0 E2 A3 B7 E2 A1 A7 E2 A1 A2 E2 A0 84 E2
         A0 84 E2 A0 84 E2 A0 84 E2 A0 A0 E2 A2 A0 E2 A1
         9B E2 A0 BF E2 A0 84 E2 A0 A0 E2 A0 AC E2 A0 BF
         E2 A3 BF E2 A0 AD E2 A0 AD E2 A2 B1 E2 A3 87 E2
         A3 80 E2 A3 AD E2 A1 85 E2 A0 B6 E2 A3 BE E2 A3
         B7 E2 A3 B6
      }
      $art4 = {
         E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2
         A0 80 E2 A0 80 E2 A0 80 E2 A2 80 E2 A3 B4 E2 A3
         BF E2 A1 BF E2 A0 9B E2 A0 89 E2 A0 99 E2 A0 9B
         E2 A0 9B E2 A0 9B E2 A0 9B E2 A0 BB E2 A2 BF E2
         A3 BF E2 A3 B7 E2 A3 A4 E2 A1 80 E2 A0 80 E2 A0
         80 E2 A0 80 E2 A0 80 E2 A0 80
      }
      $art5 = {
         E2 A0 80 E2 A2 B0 E2 A3 BF E2 A1 9F E2 A0 8B E2
         A0 89 E2 A3 B9 E2 A3 BF E2 A1 87 E2 A0 80 E2 A0
         80 E2 A0 80 E2 A0 98 E2 A3 BF E2 A3 BF E2 A3 BF
         E2 A3 BF E2 A3 B7 E2 A3 A6 E2 A3 A4 E2 A3 A4 E2
         A3 A4 E2 A3 B6 E2 A3 B6 E2 A3 B6 E2 A3 B6 E2 A3
         BF E2 A3 BF E2 A3 BF E2 A0 80
      }
      $art6 = {
         E2 A0 80 E2 A0 80 E2 A2 B8 E2 A3 AF E2 A1 AD E2
         A0 81 E2 A0 B8 E2 A3 9B E2 A3 9F E2 A0 86 E2 A1
         B4 E2 A3 BB E2 A1 B2 E2 A3 BF E2 A0 80 E2 A3 B8
         E2 A0 80 E2 A0 80 4F 4B E2 A0 80 20 E2 A1 87 20
         20 20 20
      }
      $art7 = {
         E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A3 A0 E2
         A3 B6 E2 A1 BE E2 A0 8F E2 A0 89 E2 A0 99 E2 A0
         B3 E2 A2 A6 E2 A1 80 E2 A0 80 E2 A0 80 E2 A0 80
         E2 A2 A0 E2 A0 9E E2 A0 89 E2 A0 99 E2 A0 B2 E2
         A1 80 E2 A0 80 20 20 20 20
      }
      $art8 = {
         E2 A0 80 E2 A0 80 E2 A0 80 E2 A2 80 E2 A1 BE E2
         A3 81 E2 A3 80 E2 A0 80 E2 A0 B4 E2 A0 82 E2 A0
         99 E2 A3 97 E2 A1 80 E2 A0 80 E2 A2 BB E2 A3 BF
         E2 A3 BF E2 A0 AD E2 A2 A4 E2 A3 B4 E2 A3 A6 E2
         A3 A4 E2 A3 B9 E2 A0 80 E2 A0 80 E2 A0 80 E2 A2
         80 E2 A2 B4 E2 A3 B6 E2 A3 86
      }
      $art9 = {
         E2 A0 80 E2 A0 80 E2 A2 80 E2 A3 BE E2 A3 BF E2
         A3 BF E2 A3 BF E2 A3 B7 E2 A3 AE E2 A3 BD E2 A3
         BE E2 A3 BF E2 A3 A5 E2 A3 B4 E2 A3 BF E2 A3 BF
         E2 A1 BF E2 A2 82 E2 A0 94 E2 A2 9A E2 A1 BF E2
         A2 BF E2 A3 BF E2 A3 A6 E2 A3 B4 E2 A3 BE E2 A0
         81 E2 A0 B8 E2 A3 BC E2 A1 BF
      }
      $art10 = {
         E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2
         A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0
         80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80
         E2 A0 80 E2 A0 80 E2 A0 80 E2 A2 80 E2 A3 A0 E2
         A3 B4 E2 A3 BE E2 A1 86 E2 A0 B8 E2 A3 BF E2 A3
         BF E2 A3 BF E2 A1 B7 E2 A0 82 E2 A0 A8 E2 A3 BF
         E2 A3 BF E2 A3 BF E2 A3 BF E2 A3 B6 E2 A3 A6 E2
         A3 A4 E2 A3 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0
         80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80
         E2 A0 80 E2 A0 80
      }
      $art11 = {
         E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2
         A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0
         80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80
         E2 A0 80 E2 A3 A4 E2 A3 BE E2 A3 BF E2 A3 BF E2
         A3 BF E2 A3 BF E2 A1 87 E2 A2 80 E2 A3 BF E2 A1
         BF E2 A0 8B E2 A0 81 E2 A2 80 E2 A1 B6 E2 A0 AA
         E2 A3 89 E2 A2 B8 E2 A3 BF E2 A3 BF E2 A3 BF E2
         A3 BF E2 A3 BF E2 A3 87 E2 A0 80 E2 A0 80 E2 A0
         80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80 E2 A0 80
         E2 A0 80 E2 A0 80
      }
      $art12 = {
         E2 A0 80 E2 A3 B0 E2 A1 BF E2 A3 BF E2 A3 A7 E2
         A1 90 E2 A0 84 E2 A0 B1 E2 A3 BF E2 A3 BA E2 A3
         BD E2 A2 9F E2 A3 BF E2 A3 BF E2 A2 BF E2 A3 BF
         E2 A3 8D E2 A0 89 E2 A2 80 E2 A3 80 E2 A3 90 E2
         A3 BC E2 A3 AF E2 A1 97 E2 A0 9F E2 A1 8F E2 A0
         80 E2 A0 80 E2 A0 80 E2 A0 80
      }
      $art13 = {
         20 E2 A0 81 E2 A1 BC E2 A0 8B E2 A0 80 E2 A3 86
         E2 A0 80 E2 A0 80 E2 A3 B0 E2 A3 BF E2 A3 AB E2
         A3 BE E2 A2 BF E2 A3 BF E2 A3 BF E2 A0 8D E2 A2
         A0 E2 A0 A0 E2 A0 80 E2 A0 80 E2 A2 80 E2 A0 B0
         E2 A2 BE E2 A3 BA E2 A3 BB E2 A3 BF E2 A3 BF E2
         A3 BF E2 A3 B7 E2 A1 80 E2 A0 80
      }
   condition:
      uint32be(0) == 0xCAFEBABE and filesize < 16MB
      and $field and $descriptor and 2 of ($art*)
}
