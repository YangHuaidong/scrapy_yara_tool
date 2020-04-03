rule Duqu2_Sample1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-07-02"
    description = "Detects malware - Duqu2 (cross-matches with IronTiger malware and Derusbi)"
    family = "None"
    hacker = "None"
    hash1 = "6b146e3a59025d7085127b552494e8aaf76450a19c249bfed0b4c09f328e564f"
    hash2 = "8e97c371633d285cd8fc842f4582705052a9409149ee67d97de545030787a192"
    hash3 = "2796a119171328e91648a73d95eb297edc220e8768f4bbba5fb7237122a988fc"
    hash4 = "5559fcc93eef38a1c22db66a3e0f9e9f026c99e741cc8b1a4980d166f2696188"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
    $s2 = "MSI.dll" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 40KB and $x1 ) or ( all of them )
}