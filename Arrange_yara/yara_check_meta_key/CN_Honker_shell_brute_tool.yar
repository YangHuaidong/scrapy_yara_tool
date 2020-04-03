rule CN_Honker_shell_brute_tool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file shell_brute_tool.exe"
    family = "None"
    hacker = "None"
    hash = "f6903a15453698c35dce841e4d09c542f9480f01"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "http://24hack.com/xyadmin.asp" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}