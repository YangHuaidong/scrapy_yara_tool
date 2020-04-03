rule Equation_Kaspersky_TripleFantasy_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/02/16"
    description = "Equation Group Malware - TripleFantasy http://goo.gl/ivt8EW"
    family = "None"
    hacker = "None"
    hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/ivt8EW"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "%SystemRoot%\\system32\\hnetcfg.dll" fullword wide
    $s1 = "%WINDIR%\\System32\\ahlhcib.dll" fullword wide
    $s2 = "%WINDIR%\\sjyntmv.dat" fullword wide
    $s3 = "Global\\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword wide
    $s4 = "%WINDIR%\\System32\\owrwbsdi" fullword wide
    $s5 = "Chrome" fullword wide
    $s6 = "StringIndex" fullword ascii
    $x1 = "itemagic.net@443" fullword wide
    $x2 = "team4heat.net@443" fullword wide
    $x5 = "62.216.152.69@443" fullword wide
    $x6 = "84.233.205.37@443" fullword wide
    $z1 = "www.microsoft.com@80" fullword wide
    $z2 = "www.google.com@80" fullword wide
    $z3 = "127.0.0.1:3128" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 300000 and
    ( all of ($s*) and all of ($z*) ) or
    ( all of ($s*) and 1 of ($x*) )
}