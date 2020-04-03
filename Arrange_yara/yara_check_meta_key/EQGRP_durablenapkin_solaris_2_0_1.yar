rule EQGRP_durablenapkin_solaris_2_0_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-15"
    description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
    $s2 = "send_request: putmsg \"%s\": %s" fullword ascii
    $s3 = "port undefined" fullword ascii
    $s4 = "recv_ack: %s getmsg: %s" fullword ascii
    $s5 = ">> %d -- %d" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 40KB and 2 of them )
}