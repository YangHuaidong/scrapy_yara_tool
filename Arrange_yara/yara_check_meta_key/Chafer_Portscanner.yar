rule Chafer_Portscanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-22"
    description = "Detects Custom Portscanner used by Oilrig"
    family = "None"
    hacker = "None"
    hash1 = "88274a68a6e07bdc53171641e7349d6d0c71670bd347f11dcc83306fe06656e9"
    judge = "black"
    reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "C:\\Users\\RS01204N\\Documents\\" ascii
    $x2 = "PortScanner /ip:google.com  /port:80 /t:500 /tout:2" fullword ascii
    $x3 = "open ports of host/hosts" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}