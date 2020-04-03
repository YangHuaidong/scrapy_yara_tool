rule EquationGroup_Toolset_Apr17_GangsterThief_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "50b269bda5fedcf5a62ee0514c4b14d48d53dd18ac3075dcc80b52d0c2783e06"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\\\.\\%s:" fullword wide
    $s4 = "raw_open CreateFile error" fullword ascii
    $s5 = "-PATHDELETED-" fullword ascii
    $s6 = "(deleted)" fullword wide
    $s8 = "NULLFILENAME" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}