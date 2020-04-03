rule BronzeButler_DGet_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-14"
    description = "Detects malware / hacktool sample from Bronze Butler incident"
    family = "None"
    hacker = "None"
    hash1 = "bd81521445639aaa5e3bcb5ece94f73feda3a91880a34a01f92639f8640251d6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "DGet Tool Made by XZ" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 10KB and 1 of them )
}