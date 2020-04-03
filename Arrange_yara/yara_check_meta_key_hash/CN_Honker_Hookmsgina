rule CN_Honker_Hookmsgina {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Hookmsgina.dll"
    family = "None"
    hacker = "None"
    hash = "f4d9b329b45fbcf6a3b9f29f2633d5d3d76c9f9d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\\\.\\pipe\\WinlogonHack" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "%s?host=%s&domain=%s&user=%s&pass=%s&port=%u" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "Global\\WinlogonHack_Load%u" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "Hookmsgina.dll" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}