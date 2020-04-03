rule COZY_FANCY_BEAR_Hunt {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-14"
    description = "Detects Cozy Bear / Fancy Bear C2 Server IPs"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "185.100.84.134" ascii wide fullword
    $s2 = "58.49.58.58" ascii wide fullword
    $s3 = "218.1.98.203" ascii wide fullword
    $s4 = "187.33.33.8" ascii wide fullword
    $s5 = "185.86.148.227" ascii wide fullword
    $s6 = "45.32.129.185" ascii wide fullword
    $s7 = "23.227.196.217" ascii wide fullword
  condition:
    uint16(0) == 0x5a4d and 1 of them
}