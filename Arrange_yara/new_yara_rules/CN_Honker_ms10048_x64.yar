rule CN_Honker_ms10048_x64 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file ms10048-x64.exe"
    family = "None"
    hacker = "None"
    hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[ ] Creating evil window" fullword ascii
    $s2 = "[+] Set to %d exploit half succeeded" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 125KB and all of them
}