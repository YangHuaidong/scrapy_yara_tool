import "pe"
rule MAL_CrypRAT_Jan19_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-01-07"
    description = "Detects CrypRAT"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 90
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Cryp_RAT" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and (
    pe.imphash() == "2524e5e9fe04d7bfe5efb3a5e400fe4b" or
    1 of them
}