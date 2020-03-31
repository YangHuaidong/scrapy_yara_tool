rule Equation_Kaspersky_EOP_Package {
  meta:
    author = Spider
    comment = None
    date = 2015/02/16
    description = Equation Group Malware - EoP package and malware launcher
    family = Package
    hacker = None
    hash = 2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://goo.gl/ivt8EW
    threatname = Equation[Kaspersky]/EOP.Package
    threattype = Kaspersky
  strings:
    $s0 = "abababababab" fullword ascii
    $s1 = "abcdefghijklmnopq" fullword ascii
    $s2 = "@STATIC" fullword wide
    $s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
    $s4 = "@prkMtx" fullword wide
    $s5 = "prkMtx" fullword wide
    $s6 = "cnFormVoidFBC" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 100000 and all of ($s*)
}