rule EQGRP_tinyexec {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - from files tinyexec"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = { 73 68 73 74 72 74 61 62 00 2e 74 65 78 74 }
    $s2 = { 5a 58 55 52 89 e2 55 50 89 e1 }
  condition:
    uint32(0) == 0x464c457f and filesize < 270 and all of them
}