rule CN_Honker_Htran_V2_40_htran20 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file htran20.exe"
    family = "None"
    hacker = "None"
    hash = "b992bf5b04d362ed3757e90e57bc5d6b2a04e65c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%s -slave  ConnectHost ConnectPort TransmitHost TransmitPort" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "[SERVER]connection to %s:%d error" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "%s -connect ConnectHost [ConnectPort]       Default:%d" fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "[+] got, ip:%s, port:%d" fullword ascii /* PEStudio Blacklist: strings */
    $s6 = "[-] There is a error...Create a new connection." fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}