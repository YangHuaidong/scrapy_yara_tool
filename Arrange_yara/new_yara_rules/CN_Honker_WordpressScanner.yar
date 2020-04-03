rule CN_Honker_WordpressScanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file WordpressScanner.exe"
    family = "None"
    hacker = "None"
    hash = "0b3c5015ba3616cbc616fc9ba805fea73e98bc83"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
    $s1 = "(http://www.eyuyan.com)" fullword wide
    $s2 = "GetConnectString" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "#if !defined(AFX_RESOURCE_DLL) || defined(AFX_TARG_CHS)" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}