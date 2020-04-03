rule EnigmaPacker_Rare {
   meta:
      description = "Detects an ENIGMA packed executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-27"
      score = 60
      hash1 = "77be6e80a4cfecaf50d94ee35ddc786ba1374f9fe50546f1a3382883cb14cec9"
   strings:
      $s1 = "P.rel$oc$" fullword ascii
      $s2 = "ENIGMA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and all of them )
}