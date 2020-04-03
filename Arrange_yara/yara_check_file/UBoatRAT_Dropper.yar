rule UBoatRAT_Dropper {
   meta:
      description = "Detects UBoatRAT Dropper"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/"
      date = "2017-11-29"
      hash1 = "f4c659238ffab95e87894d2c556f887774dce2431e8cb87f881df4e4d26253a3"
   strings:
      $s1 = "GetCurrenvackageId" fullword ascii
      $s2 = "fghijklmnopq" fullword ascii
      $s3 = "23456789:;<=>?@ABCDEFGHIJKLMNOPQ" fullword ascii
      $s4 = "PMM/dd/y" fullword ascii
      $s5 = "bad all" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}