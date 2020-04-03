rule EquationGroup_EquationDrug_msgkd {
   meta:
      description = "EquationGroup Malware - file msgkd.ex_"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "25eec68fc9f0d8d1b5d72c9eae7bee29035918e9dcbeab13e276dec4b2ad2a56"
   strings:
      $s1 = "KEysud" fullword ascii
      $s2 = "XWWWPWS" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}