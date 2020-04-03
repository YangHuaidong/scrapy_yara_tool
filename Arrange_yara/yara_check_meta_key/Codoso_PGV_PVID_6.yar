rule Codoso_PGV_PVID_6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-30"
    description = "Detects Codoso APT PGV_PVID Malware"
    family = "None"
    hacker = "None"
    hash = "4b16f6e8414d4192d0286b273b254fa1bd633f5d3d07ceebd03dfdfc32d0f17f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "rundll32 \"%s\",%s" fullword ascii
    $s1 = "/c ping 127.%d & del \"%s\"" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}