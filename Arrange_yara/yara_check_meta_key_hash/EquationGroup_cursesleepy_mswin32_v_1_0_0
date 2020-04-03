rule EquationGroup_cursesleepy_mswin32_v_1_0_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "6293439b4b49e94f923c76e302f5fc437023c91e063e67877d22333f05a24352"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "A}%j,R" fullword ascii
    $op1 = { a1 e0 43 41 00 8b 0d 34 44 41 00 6b c0 } /* Opcode */
    $op2 = { 33 c0 f3 a6 74 14 8b 5d 08 8b 4b 34 50 } /* Opcode */
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}