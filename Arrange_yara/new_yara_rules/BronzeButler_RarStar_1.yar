rule BronzeButler_RarStar_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-14"
    description = "Detects malware / hacktool sample from Bronze Butler incident"
    family = "None"
    hacker = "None"
    hash1 = "0fc1b4fdf0dc5373f98de8817da9380479606f775f5aa0b9b0e1a78d4b49e5f4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+6.0;+SV1)" fullword wide
    $s2 = "http://www.google.co.jp" fullword wide
    $s3 = "16D73E22-873D-D58E-4F42-E6055BC9825E" fullword ascii
    $s4 = "\\*.rar" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}