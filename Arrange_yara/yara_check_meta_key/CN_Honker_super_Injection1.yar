rule CN_Honker_super_Injection1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file super Injection1.exe"
    family = "None"
    hacker = "None"
    hash = "8ff2df40c461f6c42b92b86095296187f2b59b14"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
    $s4 = "ScanInject.log" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}