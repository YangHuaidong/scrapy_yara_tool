rule EquationGroup_PortMap_Lp {
   meta:
      description = "EquationGroup Malware - file PortMap_Lp.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "2b27f2faae9de6330f17f60a1d19f9831336f57fdfef06c3b8876498882624a6"
   strings:
      $s1 = "Privilege elevation failed" fullword wide
      $s2 = "Portmap ended due to max number of ports" fullword wide
      $s3 = "Invalid parameters received for portmap" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}