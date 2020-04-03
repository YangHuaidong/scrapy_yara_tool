rule EquationGroup_scanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file scanner"
    family = "None"
    hacker = "None"
    hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "program version netid     address             service         owner" fullword ascii
    $x4 = "*** Sorry about the raw output, I'll leave it for now" fullword ascii
    $x5 = "-scan winn %s one" fullword ascii
  condition:
    filesize < 250KB and 1 of them
}