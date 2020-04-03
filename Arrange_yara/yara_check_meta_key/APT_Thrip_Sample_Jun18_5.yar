rule APT_Thrip_Sample_Jun18_5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-21"
    description = "Detects sample found in Thrip report by Symantec "
    family = "None"
    hacker = "None"
    hash1 = "32889639a27961497d53176765b3addf9fff27f1c8cc41634a365085d6d55920"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "c:\\windows\\USBEvent.exe" fullword ascii
    $s5 = "c:\\windows\\spdir.dat" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}