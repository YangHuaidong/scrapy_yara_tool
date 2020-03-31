rule Lazagne_PW_Dumper {
   meta:
      description = "Detects Lazagne PW Dumper"
      author = "Markus Neis / Florian Roth"
      reference = "https://github.com/AlessandroZ/LaZagne/releases/"
      date = "2018-03-22"
      score = 70
   strings:
      $s1 = "Crypto.Hash" fullword ascii
      $s2 = "laZagne" fullword ascii
      $s3 = "impacket.winregistry" fullword ascii
   condition:
      3 of them
}