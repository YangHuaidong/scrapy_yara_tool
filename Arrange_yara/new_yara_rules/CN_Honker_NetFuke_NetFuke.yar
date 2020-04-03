rule CN_Honker_NetFuke_NetFuke {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file NetFuke.exe"
    family = "None"
    hacker = "None"
    hash = "f89e223fd4f6f5a3c2a2ea225660ef0957fc07ba"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Mac Flood: Flooding %dT %d p/s " fullword ascii
    $s2 = "netfuke_%s.txt" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1840KB and all of them
}