rule CN_Honker_F4ck_Team_F4ck_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file F4ck_3.exe"
    family = "None"
    hacker = "None"
    hash = "0b3e9381930f02e170e484f12233bbeb556f3731"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "F4ck.exe" fullword wide
    $s2 = "@Netapi32.dll" fullword ascii
    $s3 = "Team.F4ck.Net" fullword wide
    $s6 = "NO Net Add User" fullword wide
    $s7 = "DLL ERROR" fullword ascii
    $s11 = "F4ck Team" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}