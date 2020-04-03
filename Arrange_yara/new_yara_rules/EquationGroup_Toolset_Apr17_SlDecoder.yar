rule EquationGroup_Toolset_Apr17_SlDecoder {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "b220f51ca56d9f9d7d899fa240d3328535f48184d136013fd808d8835919f9ce"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Error in conversion. SlDecoder.exe <input filename> <output filename> at command line " fullword wide
    $x2 = "KeyLogger_Data" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}