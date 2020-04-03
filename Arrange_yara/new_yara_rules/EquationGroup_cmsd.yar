rule EquationGroup_cmsd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file cmsd"
    family = "None"
    hacker = "None"
    hash1 = "634c50614e1f5f132f49ae204c4a28f62a32a39a3446084db5b0b49b564034b8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "usage: %s address [-t][-s|-c command] [-p port] [-v 5|6|7]" fullword ascii
    $x2 = "error: not vulnerable" fullword ascii
    $s1 = "port=%d connected! " fullword ascii
    $s2 = "xxx.XXXXXX" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 30KB and 1 of ($x*) ) or ( 2 of them )
}