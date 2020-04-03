rule Saudi_Phish_Trojan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-12"
    description = "Detects a trojan used in Saudi Aramco Phishing"
    family = "None"
    hacker = "None"
    hash1 = "8ad94dc5d59aa1e9962c76fd5ca042e582566049a97aef9f5730ba779e5ebb91"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/Z3JUAA"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = { 7B 00 30 00 7D 00 7B 00 31 00 7D 00 5C 00 00 09
    2E 00 64 00 6C 00 6C 00 00 11 77 00 33 00 77 00
    70 00 2E 00 65 00 78 00 65 00 00 1B 61 00 73 00
    70 00 6E 00 65 00 74 00 5F 00 77 00 70 00 2E 00
    65 00 78 00 65 }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them )
}