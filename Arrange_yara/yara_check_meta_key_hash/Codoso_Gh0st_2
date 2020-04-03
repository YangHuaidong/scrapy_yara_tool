rule Codoso_Gh0st_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-30"
    description = "Detects Codoso APT Gh0st Malware"
    family = "None"
    hacker = "None"
    hash = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "cmd.exe /c ping 127.0.0.1 && ping 127.0.0.1 && sc start %s && ping 127.0.0.1 && sc start %s" fullword ascii
    $s1 = "rundll32.exe \"%s\", RunMeByDLL32" fullword ascii
    $s13 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
    $s14 = "%s -r debug 1" fullword ascii
    $s15 = "\\\\.\\keymmdrv1" fullword ascii
    $s17 = "RunMeByDLL32" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and 1 of them
}