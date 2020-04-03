rule EQGRP_BBALL_M50FW08_2201 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
    family = "None"
    hacker = "None"
    hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".got_loader" fullword ascii
    $s2 = "LOADED" fullword ascii
    $s3 = "pageTable.c" fullword ascii
    $s4 = "_start_text" fullword ascii
    $s5 = "handler_readBIOS" fullword ascii
    $s6 = "KEEPGOING" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 40KB and 5 of ($s*) )
}