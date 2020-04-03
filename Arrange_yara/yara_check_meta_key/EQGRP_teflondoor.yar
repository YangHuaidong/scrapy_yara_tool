rule EQGRP_teflondoor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-15"
    description = "Detects tool from EQGRP toolset - file teflondoor.exe"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "%s: abort.  Code is %d.  Message is '%s'" fullword ascii
    $x2 = "%s: %li b (%li%%)" fullword ascii
    $s1 = "no winsock" fullword ascii
    $s2 = "%s: %s file '%s'" fullword ascii
    $s3 = "peer: connect" fullword ascii
    $s4 = "read: write" fullword ascii
    $s5 = "%s: done!" fullword ascii
    $s6 = "%s: %li b" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 30KB and 1 of ($x*) and 3 of them
}