rule Xtreme_Sep17_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-27"
    description = "Detects XTREME sample analyzed in September 2017"
    family = "None"
    hacker = "None"
    hash1 = "f8413827c52a5b073bdff657d6a277fdbfda29d909b4247982f6973424fa2dcc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Spy24.exe" fullword wide
    $s2 = "Remote Service Application" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 3000KB and all of them )
}