rule splitjoin {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
    family = "None"
    hacker = "None"
    hash = "e4a9ef5d417038c4c76b72b5a636769a98bd2f8c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Not for distribution without the authors permission" fullword wide
    $s2 = "Utility to split and rejoin files.0" fullword wide
    $s5 = "Copyright (c) Angus Johnson 2001-2002" fullword wide
    $s19 = "SplitJoin" fullword wide
  condition:
    all of them
}