rule Sphinx_Moth_cudacrt {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-06"
    description = "sphinx moth threat group file cudacrt.dll"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "www.kudelskisecurity.com"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "HPSSOEx.dll" fullword wide
    $s1 = "255.255.255.254" fullword wide
    $s2 = "SOFTWARE\\SsoAuth\\Service" fullword wide
    $op0 = { ff 15 5f de 00 00 48 8b f8 48 85 c0 75 0d 48 8b } /* Opcode */
    $op1 = { 45 33 c9 4c 8d 05 a7 07 00 00 33 d2 33 c9 ff 15 } /* Opcode */
    $op2 = { e8 7a 1c 00 00 83 f8 01 74 17 b9 03 } /* Opcode */
  condition:
    uint16(0) == 0x5a4d and filesize < 243KB and all of ($s*) and 1 of ($op*)
}