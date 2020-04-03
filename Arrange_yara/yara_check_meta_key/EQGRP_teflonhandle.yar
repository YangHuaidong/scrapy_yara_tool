rule EQGRP_teflonhandle {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-15"
    description = "Detects tool from EQGRP toolset - file teflonhandle.exe"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%s [infile] [outfile] /k 0x[%i character hex key] </g>" fullword ascii
    $s2 = "File %s already exists.  Overwrite? (y/n) " fullword ascii
    $s3 = "Random Key : 0x" fullword ascii
    $s4 = "done (%i bytes written)." fullword ascii
    $s5 = "%s --> %s..." fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 20KB and 2 of them
}