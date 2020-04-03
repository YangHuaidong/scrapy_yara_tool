rule EQGRP_payload {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file payload.py"
    family = "None"
    hacker = "None"
    hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "can't find target version module!" fullword ascii
    $s2 = "class Payload:" fullword ascii
  condition:
    all of them
}