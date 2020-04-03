rule EquationGroup_PC_Level3_http_flav_dll {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file PC_Level3_http_flav_dll"
    family = "None"
    hacker = "None"
    hash1 = "27972d636b05a794d17cb3203d537bcf7c379fafd1802792e7fb8e72f130a0c4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Psxssdll.dll" fullword wide
    $s2 = "Posix Server Dll" fullword wide
    $s4 = "itanium" fullword wide
    $s5 = "RHTTP/1.0" fullword wide
    $s8 = "Copyright (C) Microsoft" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}