rule arpsniffer {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file arpsniffer.exe"
    family = "None"
    hacker = "None"
    hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "SHELL" ascii
    $s2 = "PacketSendPacket" fullword ascii
    $s3 = "ArpSniff" ascii
    $s4 = "pcap_loop" fullword ascii  /* Goodware String - occured 3 times */
    $s5 = "packet.dll" fullword ascii  /* Goodware String - occured 4 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 120KB and all of them
}