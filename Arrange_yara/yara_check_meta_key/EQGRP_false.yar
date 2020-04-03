rule EQGRP_false {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-15"
    description = "Detects tool from EQGRP toolset - file false.exe"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = { 00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
    00 25 6C 75 2E 25 6C 75 2E 25 6C 75 2E 25 6C 75
    00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
    00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
    00 25 32 2E 32 58 20 00 00 0A 00 00 00 25 64 20
    2D 20 25 64 20 25 64 0A 00 25 64 0A 00 25 64 2E
    0A 00 00 00 00 25 64 2E 0A 00 00 00 00 25 64 2E
    0A 00 00 00 00 25 64 20 2D 20 25 64 0A 00 00 00
    00 25 64 20 2D 20 25 64 }
  condition:
    uint16(0) == 0x5a4d and filesize < 50KB and $s1
}