rule CN_Honker_HconSTFportable {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file HconSTFportable.exe"
    family = "None"
    hacker = "None"
    hash = "00253a00eadb3ec21a06911a3d92728bbbe80c09"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "HconSTFportable.exe" fullword wide /* PEStudio Blacklist: strings */
    $s2 = "www.Hcon.in" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 354KB and all of them
}