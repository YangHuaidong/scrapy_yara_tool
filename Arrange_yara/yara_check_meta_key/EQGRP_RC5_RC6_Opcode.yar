rule EQGRP_RC5_RC6_Opcode {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-17"
    description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"
    threatname = "None"
    threattype = "None"
  strings:
    mov     esi, [ecx+edx*4-4]
    sub     esi, 61C88647h
    mov     [ecx+edx*4], esi
    inc     edx
    cmp     edx, 2Bh
    $s1 = { 8b 74 91 fc 81 ee 47 86 c8 61 89 34 91 42 83 fa 2b }
  condition:
    1 of them
}