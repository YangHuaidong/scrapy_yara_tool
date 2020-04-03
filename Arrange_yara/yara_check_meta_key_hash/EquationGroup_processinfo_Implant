rule EquationGroup_processinfo_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file processinfo_Implant.dll"
    family = "None"
    hacker = "None"
    hash1 = "aadfa0b1aec4456b10e4fb82f5cfa918dbf4e87d19a02bcc576ac499dda0fb68"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "hZwOpenProcessToken" fullword ascii
    $s2 = "hNtQueryInformationProcess" fullword ascii
    $s3 = "No mapping" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}