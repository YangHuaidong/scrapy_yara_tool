rule EquationGroup_Toolset_Apr17_DS_ParseLogs {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "0228691d63038b072cdbf50782990d505507757efbfa87655bb2182cf6375956"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "* Size (%d) of remaining capture file is too small to contain a valid header" fullword wide
    $x2 = "* Capture header not found at start of buffer" fullword wide
    $x3 = "Usage: %ws <capture_file> <results_prefix>" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}