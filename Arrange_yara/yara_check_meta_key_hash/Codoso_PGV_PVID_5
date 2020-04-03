rule Codoso_PGV_PVID_5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-30"
    description = "Detects Codoso APT PGV PVID Malware"
    family = "None"
    hacker = "None"
    hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
    hash2 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "/c del %s >> NUL" fullword ascii
    $s2 = "%s%s.manifest" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and all of them
}