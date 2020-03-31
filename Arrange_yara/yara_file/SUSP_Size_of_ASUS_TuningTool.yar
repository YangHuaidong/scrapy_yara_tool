rule SUSP_Size_of_ASUS_TuningTool {
   meta:
      description = "Detects an ASUS tuning tool with a suspicious size"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      score = 60
      noarchivescan = 1
      hash1 = "d4e97a18be820a1a3af639c9bca21c5f85a3f49a37275b37fd012faeffcb7c4a"
   strings:
      $s1 = "\\Release\\ASGT.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and filesize > 70KB and all of them
}