rule CN_Honker_termsrvhack {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file termsrvhack.dll"
    family = "None"
    hacker = "None"
    hash = "1c456520a7b7faf71900c71167038185f5a7d312"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "The terminal server cannot issue a client license.  It was unable to issue the" wide /* PEStudio Blacklist: strings */
    $s6 = "%s\\%s\\%d\\%d" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 1052KB and all of them
}