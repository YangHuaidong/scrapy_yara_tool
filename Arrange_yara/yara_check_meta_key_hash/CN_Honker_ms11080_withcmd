rule CN_Honker_ms11080_withcmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file ms11080_withcmd.exe"
    family = "None"
    hacker = "None"
    hash = "745e5058acff27b09cfd6169caf6e45097881a49"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "[>] create pipe error" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 340KB and all of them
}