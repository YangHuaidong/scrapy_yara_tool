rule Kriskynote_Mar17_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-03"
    description = "Detects Kriskynote Malware"
    family = "None"
    hacker = "None"
    hash1 = "fc838e07834994f25b3b271611e1014b3593278f0703a4a985fb4234936df492"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "rundll32 %s Check" fullword ascii
    $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" fullword ascii
    $s3 = "name=\"IsUserAdmin\"" fullword ascii
    $s4 = "zok]\\\\\\ZZYYY666564444" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them )
}