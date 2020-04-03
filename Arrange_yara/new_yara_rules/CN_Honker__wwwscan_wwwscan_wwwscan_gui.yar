rule CN_Honker__wwwscan_wwwscan_wwwscan_gui {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - from files wwwscan.exe, wwwscan.exe, wwwscan_gui.exe"
    family = "None"
    hacker = "None"
    hash0 = "6dbffa916d0f0be2d34c8415592b9aba690634c7"
    hash1 = "6bed45629c5e54986f2d27cbfc53464108911026"
    hash2 = "897b66a34c58621190cb88e9b2a2a90bf9b71a53"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
    $s2 = "<Usage>:  %s <HostName|Ip> [Options]" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}