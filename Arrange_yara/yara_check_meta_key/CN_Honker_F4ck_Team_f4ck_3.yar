rule CN_Honker_F4ck_Team_f4ck_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file f4ck.exe"
    family = "None"
    hacker = "None"
    hash = "7e3bf9b26df08cfa10f10e2283c6f21f5a3a0014"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "File UserName PassWord [comment] /add" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "No Net.exe Add User" fullword ascii
    $s3 = "BlackMoon RunTime Error:" fullword ascii
    $s4 = "Team.F4ck.Net" fullword wide
    $s5 = "admin 123456789" fullword ascii /* PEStudio Blacklist: strings */
    $s6 = "blackmoon" fullword ascii
    $s7 = "f4ck Team" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and 4 of them
}