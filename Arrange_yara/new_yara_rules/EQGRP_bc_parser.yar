rule EQGRP_bc_parser {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-15"
    description = "Detects tool from EQGRP toolset - file bc-parser"
    family = "None"
    hacker = "None"
    hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
    $s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii
  condition:
    uint16(0) == 0x457f and 1 of them
}