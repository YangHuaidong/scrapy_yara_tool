rule EquationGroup_seconddate_ImplantStandalone_3_0_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "d687aa644095c81b53a69c206eb8d6bdfe429d7adc2a57d87baf8ff8d4233511"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "EFDGHIJKLMNOPQRSUT" fullword ascii
    $s2 = "G8HcJ HcF LcF0LcN" fullword ascii
    $s3 = "GhHcJ0HcF@LcF0LcN8H" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 1000KB and all of them )
}