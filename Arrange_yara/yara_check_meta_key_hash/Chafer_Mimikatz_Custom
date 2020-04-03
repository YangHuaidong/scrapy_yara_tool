rule Chafer_Mimikatz_Custom {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-22"
    description = "Detects Custom Mimikatz Version"
    family = "None"
    hacker = "None"
    hash1 = "9709afeb76532566ee3029ecffc76df970a60813bcac863080cc952ad512b023"
    judge = "unknown"
    reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "C:\\Users\\win7p\\Documents\\mi-back\\" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}