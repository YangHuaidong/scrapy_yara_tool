rule Xtreme_Sep17_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-27"
    description = "Detects XTREME sample analyzed in September 2017"
    family = "None"
    hacker = "None"
    hash1 = "f540a4cac716438da0c1c7b31661abf35136ea69b963e8f16846b96f8fd63dde"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Keylogg" fullword ascii
    $s4 = "XTREME" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 700KB and all of them )
}