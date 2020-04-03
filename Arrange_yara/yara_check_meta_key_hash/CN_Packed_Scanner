rule CN_Packed_Scanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "06.10.2014"
    description = "Suspiciously packed executable"
    family = "None"
    hacker = "None"
    hash = "6323b51c116a77e3fba98f7bb7ff4ac6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 40
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "kernel32.dll" fullword ascii
    $s2 = "CRTDLL.DLL" fullword ascii
    $s3 = "__GetMainArgs" fullword ascii
    $s4 = "WS2_32.DLL" fullword ascii
  condition:
    all of them and filesize < 180KB and filesize > 70KB
}