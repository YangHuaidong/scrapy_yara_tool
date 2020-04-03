rule COZY_FANCY_BEAR_pagemgr_Hunt {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-14"
    description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "pagemgr.exe" wide fullword
  condition:
    uint16(0) == 0x5a4d and 1 of them
}