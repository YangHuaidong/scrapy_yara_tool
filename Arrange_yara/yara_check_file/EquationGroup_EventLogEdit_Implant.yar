rule EquationGroup_EventLogEdit_Implant {
   meta:
      description = "EquationGroup Malware - file EventLogEdit_Implant.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "0bb750195fbd93d174c2a8e20bcbcae4efefc881f7961fdca8fa6ebd68ac1edf"
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\%ls" fullword wide
      $s2 = "Ntdll.dll" fullword ascii
      $s3 = "hZwOpenProcess" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}