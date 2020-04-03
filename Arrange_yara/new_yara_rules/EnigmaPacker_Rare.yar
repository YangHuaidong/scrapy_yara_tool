rule EnigmaPacker_Rare {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-27"
    description = "Detects an ENIGMA packed executable"
    family = "None"
    hacker = "None"
    hash1 = "77be6e80a4cfecaf50d94ee35ddc786ba1374f9fe50546f1a3382883cb14cec9"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "P.rel$oc$" fullword ascii
    $s2 = "ENIGMA" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 4000KB and all of them )
}