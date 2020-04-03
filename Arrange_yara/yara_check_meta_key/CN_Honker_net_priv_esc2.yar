rule CN_Honker_net_priv_esc2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file net-priv-esc2.exe"
    family = "None"
    hacker = "None"
    hash = "4851e0088ad38ac5b3b1c75302a73698437f7f17"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Usage:%s username password" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<www.darkst.com>" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 17KB and all of them
}