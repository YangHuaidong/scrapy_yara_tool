rule EquationGroup_envoytomato {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file envoytomato"
    family = "None"
    hacker = "None"
    hash1 = "9bd001057cc97b81fdf2450be7bf3b34f1941379e588a7173ab7fffca41d4ad5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[-] kernel not vulnerable" fullword ascii
    $s2 = "[-] failed to spawn shell" fullword ascii
  condition:
    filesize < 250KB and 1 of them
}