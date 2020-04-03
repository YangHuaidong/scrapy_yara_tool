rule lsass_ANOMALY {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/16"
    description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file lsass.exe"
    family = "None"
    hacker = "None"
    hash = "04abf92ac7571a25606edfd49dca1041c41bef21"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "not set"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "LSA Shell" fullword wide
    $s2 = "<description>Local Security Authority Process</description>" fullword ascii
    $s3 = "Local Security Authority Process" fullword wide
    $s4 = "LsapInitLsa" fullword
  condition:
    filename == "lsass.exe"
    and uint16(0) == 0x5a4d
    and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}