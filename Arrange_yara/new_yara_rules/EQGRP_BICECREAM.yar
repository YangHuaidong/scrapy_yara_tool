rule EQGRP_BICECREAM {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file BICECREAM-2140"
    family = "None"
    hacker = "None"
    hash1 = "4842076af9ba49e6dfae21cf39847b4172c06a0bd3d2f1ca6f30622e14b77210"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Could not connect to target device: %s:%d. Please check IP address." fullword ascii
    $s2 = "command data size is invalid for an exec cmd" fullword ascii
    $s3 = "A script was specified but target is not a PPC405-based NetScreen (NS5XT, NS25, and NS50). Executing scripts is supported but ma" ascii
    $s4 = "Execute 0x%08x with args (%08x, %08x, %08x, %08x): [y/n]" fullword ascii
    $s5 = "Execute 0x%08x with args (%08x, %08x, %08x): [y/n]" fullword ascii
    $s6 = "[%d] Execute code." fullword ascii
    $s7 = "Execute 0x%08x with args (%08x): [y/n]" fullword ascii
    $s8 = "dump_value_LHASH_DOALL_ARG" fullword ascii
    $s9 = "Eggcode is complete. Pass execution to it? [y/n]" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 5000KB and 2 of them ) or ( 5 of them )
}