rule EQGRP_BPATROL_2201 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file BPATROL-2201.exe"
    family = "None"
    hacker = "None"
    hash1 = "aa892750b893033eed2fedb2f4d872f79421174eb217f0c34a933c424ae66395"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "dumpConfig" fullword ascii
    $s2 = "getstatusHandler" fullword ascii
    $s3 = ".got_loader" fullword ascii
    $s4 = "xtractdata" fullword ascii
    $s5 = "KEEPGOING" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 40KB and all of them )
}