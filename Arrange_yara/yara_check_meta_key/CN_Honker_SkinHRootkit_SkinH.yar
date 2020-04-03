rule CN_Honker_SkinHRootkit_SkinH {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file SkinH.exe"
    family = "None"
    hacker = "None"
    hash = "d593f03ae06e54b653c7850c872c0eed459b301f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "(C)360.cn Inc.All Rights Reserved." fullword wide
    $s1 = "SDVersion.dll" fullword wide
    $s2 = "skinh.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}