rule CN_Honker_WebScan_WebScan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file WebScan.exe"
    family = "None"
    hacker = "None"
    hash = "a0b0e2422e0e9edb1aed6abb5d2e3d156b7c8204"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "wwwscan.exe" fullword wide /* PEStudio Blacklist: strings */
    $s2 = "WWWScan Gui" fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and all of them
}