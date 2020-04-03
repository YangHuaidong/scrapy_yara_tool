rule EquationGroup_PC_Level3_http_flav_dll_x64 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file PC_Level3_http_flav_dll_x64"
    family = "None"
    hacker = "None"
    hash1 = "4e0209b4f5990148f5d6dee47dbc7021bf78a782b85cef4d6c8be22d698b884f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Psxssdll.dll" fullword wide
    $s2 = "Posix Server Dll" fullword wide
    $s3 = ".?AVOpenSocket@@" fullword ascii
    $s4 = "RHTTP/1.0" fullword wide
    $s5 = "Copyright (C) Microsoft" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 400KB and ( all of ($s*) ) ) or ( all of them )
}