rule EQGRP_dn_1_0_2_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-15"
    description = "Detects tool from EQGRP toolset - file dn.1.0.2.1.linux"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Valid commands are: SMAC, DMAC, INT, PACK, DONE, GO" fullword ascii
    $s2 = "invalid format suggest DMAC=00:00:00:00:00:00" fullword ascii
    $s3 = "SMAC=%02x:%02x:%02x:%02x:%02x:%02x" fullword ascii
    $s4 = "Not everything is set yet" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 30KB and 2 of them )
}