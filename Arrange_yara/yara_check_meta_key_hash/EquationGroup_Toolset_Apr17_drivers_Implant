rule EquationGroup_Toolset_Apr17_drivers_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "ee8b048f1c6ba821d92c15d614c2d937c32aeda7b7ea0943fd4f640b57b1c1ab"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".?AVFeFinallyFailure@@" fullword ascii
    $s2 = "hZwLoadDriver" fullword ascii
    $op1 = { b0 01 e8 58 04 00 00 c3 33 }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}