rule EquationGroup_curseflower_mswin32_v_1_0_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "fdc452629ff7befe02adea3a135c3744d8585af890a4301b2a10a817e48c5cbf"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<pVt,<et(<st$<ct$<nt" fullword ascii
    $op1 = { 6a 04 83 c0 08 6a 01 50 e8 10 34 00 00 83 c4 10 } /* Opcode */
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}