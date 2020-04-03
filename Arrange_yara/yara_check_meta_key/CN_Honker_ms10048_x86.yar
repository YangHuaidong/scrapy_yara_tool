rule CN_Honker_ms10048_x86 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file ms10048-x86.exe"
    family = "None"
    hacker = "None"
    hash = "e57b453966e4827e2effa4e153f2923e7d058702"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[+] Set to %d exploit half succeeded" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 30KB and all of them
}