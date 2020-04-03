rule CN_Honker_syconfig {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file syconfig.dll"
    family = "None"
    hacker = "None"
    hash = "ff75353df77d610d3bccfbffb2c9dfa258b2fac9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s9 = "Hashq.CrackHost+FormUnit" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x0100 and filesize < 18KB and all of them
}