rule EQGRP_BARPUNCH_BPICKER {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BPICKER-3100"
    family = "None"
    hacker = "None"
    hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
    hash2 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s --lptimeout %u" fullword ascii
    $x2 = "%s -c <cmdtype> -l <lp> -i <implant> -k <ikey> -s <port> -d <port> [operation] [options]" fullword ascii
    $x3 = "* [%lu] 0x%x is marked as stateless (the module will be persisted without its configuration)" fullword ascii
    $x4 = "%s version %s already has persistence installed. If you want to uninstall," fullword ascii
    $x5 = "The active module(s) on the target are not meant to be persisted" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 6000KB and 1 of them ) or ( 3 of them )
}