rule CN_Honker_Fckeditor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Fckeditor.exe"
    family = "None"
    hacker = "None"
    hash = "4b16ae12c204f64265acef872526b27111b68820"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "explorer.exe http://user.qzone.qq.com/568148075" fullword wide /* PEStudio Blacklist: strings */
    $s7 = "Fckeditor.exe" fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 1340KB and all of them
}