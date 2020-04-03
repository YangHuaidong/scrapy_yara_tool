rule APT_Thrip_Sample_Jun18_10 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-21"
    description = "Detects sample found in Thrip report by Symantec "
    family = "None"
    hacker = "None"
    hash1 = "350d2a6f8e6a4969ffbf75d9f9aae99e7b3a8cd8708fd66f977e07d7fbf842e3"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "!This Program cannot be run in DOS mode." fullword ascii
    $x2 = "!this program cannot be run in dos mode." fullword ascii
    $s1 = "svchost.dll" fullword ascii
    $s2 = "constructor or from DllMain." fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and ( $x1 or 2 of them )
}