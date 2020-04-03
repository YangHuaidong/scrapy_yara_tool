rule EquationGroup_Toolset_Apr17_SetCallback {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "a8854f6b01d0e49beeb2d09e9781a6837a0d18129380c6e1b1629bc7c13fdea2"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "*NOTE: This version of SetCallback does not work with PeddleCheap versions prior" fullword ascii
    $s3 = "USAGE: SetCallback <input file> <output file>" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}