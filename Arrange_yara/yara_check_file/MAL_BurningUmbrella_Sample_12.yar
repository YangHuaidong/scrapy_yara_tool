rule MAL_BurningUmbrella_Sample_12 {
  meta:
    author = Spider
    comment = None
    date = 2018-05-04
    description = Detects malware sample from Burning Umbrella report
    family = 12
    hacker = None
    hash1 = b9aba520eeaf6511877c1eec5f7d71e0eea017312a104f30d3b8f17c89db47e8
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://401trg.pw/burning-umbrella/
    threatname = MAL[BurningUmbrella]/Sample.12
    threattype = BurningUmbrella
  strings:
    $s1 = "%SystemRoot%\\System32\\qmgr.dll" fullword ascii
    $s2 = "rundll32.exe %s,Startup" fullword ascii
    $s3 = "nvsvcs.dll" fullword wide
    $s4 = "SYSTEM\\CurrentControlSet\\services\\BITS\\Parameters" fullword ascii
    $s5 = "http://www.sginternet.net 0" fullword ascii
    $s6 = "Microsoft Corporation. All rights reserved." fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 80KB and (
    pe.exports("SvcServiceMain") and
    5 of them
}