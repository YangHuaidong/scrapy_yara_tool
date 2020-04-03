rule Regin_APT_KernelDriver_Generic_C {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
    family = "None"
    hacker = "None"
    hash1 = "e0895336617e0b45b312383814ec6783556d7635"
    hash2 = "732298fa025ed48179a3a2555b45be96f7079712"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 }
    $s0 = "KeGetCurrentIrql" fullword ascii
    $s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
    $s2 = "usbclass" fullword wide
    $x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
    $x2 = "Universal Serial Bus Class Driver" fullword wide
    $x3 = "5.2.3790.0" fullword wide
    $y1 = "LSA Shell" fullword wide
    $y2 = "0Richw" fullword ascii
  condition:
    uint16(0) == 0x5a4d and
    $m0 at 0 and all of ($s*) and
    ( all of ($x*) or all of ($y*) )
    and filesize < 20KB
}