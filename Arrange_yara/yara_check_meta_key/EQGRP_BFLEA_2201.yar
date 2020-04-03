rule EQGRP_BFLEA_2201 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file BFLEA-2201.exe"
    family = "None"
    hacker = "None"
    hash1 = "15e8c743770e44314496c5f27b6297c5d7a4af09404c4aa507757e0cc8edc79e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".got_loader" fullword ascii
    $s2 = "LOADED" fullword ascii
    $s3 = "readFlashHandler" fullword ascii
    $s4 = "KEEPGOING" fullword ascii
    $s5 = "flashRtnsPix6x.c" fullword ascii
    $s6 = "fix_ip_cksum_incr" fullword ascii
    $s7 = "writeFlashHandler" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 30KB and 5 of them ) or ( all of them )
}