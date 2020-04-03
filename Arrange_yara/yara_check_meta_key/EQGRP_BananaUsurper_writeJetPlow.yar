rule EQGRP_BananaUsurper_writeJetPlow {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, writeJetPlow-2130"
    family = "None"
    hacker = "None"
    hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
    hash2 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Implant Version-Specific Values:" fullword ascii
    $x2 = "This function should not be used with a Netscreen, something has gone horribly wrong" fullword ascii
    $s1 = "createSendRecv: recv'd an error from the target." fullword ascii
    $s2 = "Error: WatchDogTimeout read returned %d instead of 4" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 2000KB and 1 of ($x*) ) or ( 3 of them )
}