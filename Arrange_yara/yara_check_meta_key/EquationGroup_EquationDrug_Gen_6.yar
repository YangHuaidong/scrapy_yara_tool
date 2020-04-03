rule EquationGroup_EquationDrug_Gen_6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file PC_Level3_dll_x64"
    family = "None"
    hacker = "None"
    hash1 = "339855618fb3ef53987b8c14a61bd4519b2616e766149e0c21cbd7cbe7a632c9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Psxssdll.dll" fullword wide
    $s2 = "Posix Server Dll" fullword wide
    $s3 = "Copyright (C) Microsoft" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}