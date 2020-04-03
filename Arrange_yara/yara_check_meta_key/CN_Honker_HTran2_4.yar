rule CN_Honker_HTran2_4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file HTran2.4.exe"
    family = "None"
    hacker = "None"
    hash = "524f986692f55620013ab5a06bf942382e64d38a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "[+] New connection %s:%d !!" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 180KB and all of them
}