rule EquationGroup_EquationDrug_tdi6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file tdi6.sys"
    family = "None"
    hacker = "None"
    hash1 = "12c082f74c0916a0e926488642236de3a12072a18d29c97bead15bb301f4b3f8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "tdi6.sys" fullword wide
    $s3 = "TDI IPv6 Wrapper" fullword wide
    $s5 = "Corporation. All rights reserved." fullword wide
    $s6 = "FailAction" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}