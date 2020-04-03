rule EquationGroup_elgingamble {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file elgingamble"
    family = "None"
    hacker = "None"
    hash1 = "0573e12632e6c1925358f4bfecf8c263dd13edf52c633c9109fe3aae059b49dd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "* * * * * root chown root %s; chmod 4755 %s; %s" fullword ascii
    $x2 = "[-] kernel not vulnerable" fullword ascii
    $x3 = "[-] failed to spawn shell: %s" fullword ascii
    $x4 = "-s shell           Use shell instead of %s" fullword ascii
  condition:
    1 of them
}