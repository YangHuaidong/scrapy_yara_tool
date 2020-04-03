rule EquationGroup__ghost_sparc_ghost_x86_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- from files ghost_sparc, ghost_x86"
    family = "None"
    hacker = "None"
    hash1 = "d5ff0208d9532fc0c6716bd57297397c8151a01bf4f21311f24e7a72551f9bf1"
    hash2 = "82c899d1f05b50a85646a782cddb774d194ef85b74e1be642a8be2c7119f4e33"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Usage: %s [-v os] [-p] [-r] [-c command] [-a attacker] target" fullword ascii
    $x2 = "Sending shellcode as part of an open command..." fullword ascii
    $x3 = "cmdshellcode" fullword ascii
    $x4 = "You will not be able to run the shellcode. Exiting..." fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 70KB and 1 of them ) or ( 2 of them )
}