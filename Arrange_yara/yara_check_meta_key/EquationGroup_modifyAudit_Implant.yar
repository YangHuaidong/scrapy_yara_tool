rule EquationGroup_modifyAudit_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file modifyAudit_Implant.dll"
    family = "None"
    hacker = "None"
    hash1 = "b7902809a15c4c3864a14f009768693c66f9e9234204b873d29a87f4c3009a50"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "LSASS.EXE" fullword wide
    $s2 = "hNtQueryInformationProcess" fullword ascii
    $s3 = "hZwOpenProcess" fullword ascii
    $s4 = ".?AVFeFinallyFailure@@" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 90KB and ( all of ($s*) ) ) or ( all of them )
}