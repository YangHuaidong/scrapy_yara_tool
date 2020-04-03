rule EquationGroup_Toolset_Apr17_pwd_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "ee72ac76d82dfec51c8fbcfb5fc99a0a45849a4565177e01d8d23a358e52c542"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "7\"7(7/7>7O7]7o7w7" fullword ascii
    $op1 = { 40 50 89 44 24 18 ff 15 34 20 00 }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}