rule SUSP_Microsoft_RAR_SFX_Combo {
   meta:
      description = "Detects a suspicious file that has a Microsoft copyright and is a RAR SFX"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-09-16"
   strings:
      $s1 = "winrarsfxmappingfile.tmp" fullword wide
      $s2 = "WinRAR self-extracting archive" fullword wide
      $s3 = "WINRAR.SFX" fullword
      /* PE Header : LegalCopyright (C) Microsoft Corporation. All rights reserved.*/
      $c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
              00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 A9
              00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
              00 66 00 74 00 20 00 43 00 6F 00 72 00 70 00 6F
              00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20
              00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 00 68
              00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72
              00 76 00 65 00 64 00 2E }
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of ($s*) and $c1
}