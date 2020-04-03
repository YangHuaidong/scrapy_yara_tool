rule EQGRP_BPIE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file BPIE-2201.exe"
    family = "None"
    hacker = "None"
    hash1 = "697e80cf2595c85f7c931693946d295994c55da17a400f2c9674014f130b4688"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "profProcessPacket" fullword ascii
    $s2 = ".got_loader" fullword ascii
    $s3 = "getTimeSlotCmdHandler" fullword ascii
    $s4 = "getIpIpCmdHandler" fullword ascii
    $s5 = "LOADED" fullword ascii
    $s6 = "profStartScan" fullword ascii
    $s7 = "tmpData.1" fullword ascii
    $s8 = "resetCmdHandler" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 70KB and 6 of ($s*) )
}