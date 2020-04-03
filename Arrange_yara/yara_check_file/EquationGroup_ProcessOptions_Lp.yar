rule EquationGroup_ProcessOptions_Lp {
   meta:
      description = "EquationGroup Malware - file ProcessOptions_Lp.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "31d86f77137f0b3697af03dd28d6552258314cecd3c1d9dc18fcf609eb24229a"
   strings:
      $s1 = "Invalid parameter received by implant" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}