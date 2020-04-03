rule EquationGroup_EventLogEdit_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file EventLogEdit_Implant.dll"
    family = "None"
    hacker = "None"
    hash1 = "0bb750195fbd93d174c2a8e20bcbcae4efefc881f7961fdca8fa6ebd68ac1edf"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\%ls" fullword wide
    $s2 = "Ntdll.dll" fullword ascii
    $s3 = "hZwOpenProcess" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}