rule CN_Honker_Arp_EMP_v1_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Arp EMP v1.0.exe"
    family = "None"
    hacker = "None"
    hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Arp EMP v1.0.exe" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and all of them
}