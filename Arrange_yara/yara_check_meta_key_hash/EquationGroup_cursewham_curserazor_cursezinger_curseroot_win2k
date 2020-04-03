rule EquationGroup_cursewham_curserazor_cursezinger_curseroot_win2k {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "aff27115ac705859871ab1bf14137322d1722f63705d6aeada43d18966843225"
    hash2 = "7a25e26950bac51ca8d37cec945eb9c38a55fa9a53bc96da53b74378fb10b67e"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
    $s3 = ",%02d%03d" fullword ascii
    $s4 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
    $op1 = { 7d ec 8d 74 3f 01 0f af f7 c1 c6 05 } /* Opcode */
    $op2 = { 29 f1 89 fb d3 eb 89 f1 d3 e7 } /* Opcode */
    $op3 = { 7d e4 8d 5c 3f 01 0f af df c1 c3 05 } /* Opcode */
  condition:
    ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them )
}