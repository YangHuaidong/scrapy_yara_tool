rule EquationGroup__scanner_scanner_v2_1_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- from files scanner, scanner.v2.1.2"
    family = "None"
    hacker = "None"
    hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
    hash2 = "9807aaa7208ed6c5da91c7c30ca13d58d16336ebf9753a5cea513bcb59de2cff"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Welcome to the network scanning tool" fullword ascii
    $s2 = "Scanning port %d" fullword ascii
    $s3 = "/current/down/cmdout/scans" fullword ascii
    $s4 = "Scan for SSH version" fullword ascii
    $s5 = "program vers proto   port  service" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 100KB and 2 of them ) or ( all of them )
}