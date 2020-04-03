rule EquationGroup_smash {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file smash"
    family = "None"
    hacker = "None"
    hash1 = "1dc94b46aaff06d65a3bf724c8701e5f095c1c9c131b65b2f667e11b1f0129a6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "T=<target IP> [O=<port>] Y=<target type>" fullword ascii
    $x2 = "no command given!! bailing..." fullword ascii
    $x3 = "no port. assuming 22..." fullword ascii
  condition:
    filesize < 250KB and 1 of them
}