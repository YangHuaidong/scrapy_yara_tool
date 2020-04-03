rule EquationGroup_Toolset_Apr17_GrDo_FileScanner_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "8d2e43567e1360714c4271b75c21a940f6b26a789aa0fce30c6478ae4ac587e4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "system32\\winsrv.dll" fullword wide
    $s2 = "raw_open CreateFile error" fullword ascii
    $s3 = "\\dllcache\\" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}