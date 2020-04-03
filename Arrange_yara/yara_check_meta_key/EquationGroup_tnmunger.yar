rule EquationGroup_tnmunger {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file tnmunger"
    family = "None"
    hacker = "None"
    hash1 = "1ab985d84871c54d36ba4d2abd9168c2a468f1ba06994459db06be13ee3ae0d2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "TEST: mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
    $s2 = "mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 10KB and 1 of them )
}