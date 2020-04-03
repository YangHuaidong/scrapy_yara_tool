rule Equation_Kaspersky_TripleFantasy_Loader {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/02/16"
    description = "Equation Group Malware - TripleFantasy Loader"
    family = "None"
    hacker = "None"
    hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/ivt8EW"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Original Innovations, LLC" fullword wide
    $x2 = "Moniter Resource Protocol" fullword wide
    $x3 = "ahlhcib.dll" fullword wide
    $s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
    $s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
    $s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
    $s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
    $s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
    $s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 50000 and ( all of ($x*) and all of ($s*) )
}