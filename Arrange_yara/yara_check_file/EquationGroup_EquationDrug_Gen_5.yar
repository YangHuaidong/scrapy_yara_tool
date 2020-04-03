rule EquationGroup_EquationDrug_Gen_5 {
   meta:
      description = "EquationGroup Malware - file PC_Level3_http_dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "4ebfc1f6ec6a0e68e47e5b231331470a4483184cf715a578191b91ba7c32094d"
   strings:
      $s1 = "Psxssdll.dll" fullword wide
      $s2 = "Posix Server Dll" fullword wide
      $s3 = "itanium" fullword wide
      $s6 = "Copyright (C) Microsoft" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}