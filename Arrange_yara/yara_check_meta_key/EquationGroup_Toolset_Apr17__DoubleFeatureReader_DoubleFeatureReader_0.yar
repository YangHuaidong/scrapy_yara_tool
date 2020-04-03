rule EquationGroup_Toolset_Apr17__DoubleFeatureReader_DoubleFeatureReader_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "052e778c26120c683ee2d9f93677d9217e9d6c61ffc0ab19202314ab865e3927"
    hash2 = "5db457e7c7dba80383b1df0c86e94dc6859d45e1d188c576f2ba5edee139d9ae"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "DFReader.exe logfile AESKey [-j] [-o outputfilename]" fullword ascii
    $x2 = "Double Feature Target Version" fullword ascii
    $x3 = "DoubleFeature Process ID" fullword ascii
    $op1 = { a1 30 21 41 00 89 85 d8 fc ff ff a1 34 21 41 00 }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( 2 of them )
}