rule CN_Honker_dedecms5_7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file dedecms5.7.exe"
    family = "None"
    hacker = "None"
    hash = "f9cbb25883828ca266e32ff4faf62f5a9f92c5fb"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "/data/admin/ver.txt" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "SkinH_EL.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 830KB and all of them
}