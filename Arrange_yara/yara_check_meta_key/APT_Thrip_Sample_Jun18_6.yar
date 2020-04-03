rule APT_Thrip_Sample_Jun18_6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-21"
    description = "Detects sample found in Thrip report by Symantec "
    family = "None"
    hacker = "None"
    hash1 = "44f58496578e55623713c4290abb256d03103e78e99939daeec059776bd79ee2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "C:\\Windows\\system32\\Instell.exe" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}