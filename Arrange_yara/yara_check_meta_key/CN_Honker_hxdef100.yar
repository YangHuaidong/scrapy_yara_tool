rule CN_Honker_hxdef100 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file hxdef100.exe"
    family = "None"
    hacker = "None"
    hash = "bf30ccc565ac40073b867d4c7f5c33c6bc1920d6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s6 = "BACKDOORSHELL" fullword ascii /* PEStudio Blacklist: strings */
    $s15 = "%tmpdir%" fullword ascii
    $s16 = "%cmddir%" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}