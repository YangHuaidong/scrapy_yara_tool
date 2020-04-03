rule CN_Honker_hkmjjiis6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file hkmjjiis6.exe"
    family = "None"
    hacker = "None"
    hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s14 = "* FROM IIsWebInfo/r" fullword ascii
    $s19 = "ltithread4ck/" fullword ascii
    $s20 = "LookupAcc=Sid#" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 175KB and all of them
}