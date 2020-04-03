rule EquationGroup_Toolset_Apr17_Banner_Implant9x {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "5d69a8cfc9b636448f023fcf18d111f13a8e6bcb9a693eb96276e0d796ab4e0c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".?AVFeFinallyFailure@@" fullword ascii
    $op1 = { c9 c3 57 8d 85 2c eb ff ff }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 20KB and all of them )
}