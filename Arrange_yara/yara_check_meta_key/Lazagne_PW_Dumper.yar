rule Lazagne_PW_Dumper {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-22"
    description = "Detects Lazagne PW Dumper"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/AlessandroZ/LaZagne/releases/"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Crypto.Hash" fullword ascii
    $s2 = "laZagne" fullword ascii
    $s3 = "impacket.winregistry" fullword ascii
  condition:
    3 of them
}