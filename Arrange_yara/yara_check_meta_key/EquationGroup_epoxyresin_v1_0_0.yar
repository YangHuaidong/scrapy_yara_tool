rule EquationGroup_epoxyresin_v1_0_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file epoxyresin.v1.0.0.1"
    family = "None"
    hacker = "None"
    hash1 = "eea8a6a674d5063d7d6fc9fe07060f35b16172de6d273748d70576b01bf01c73"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[-] kernel not vulnerable" fullword ascii
    $s1 = ".tmp.%d.XXXXXX" fullword ascii
    $s2 = "[-] couldn't create temp file" fullword ascii
    $s3 = "/boot/System.map-%s" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 30KB and $x1 ) or ( all of them )
}