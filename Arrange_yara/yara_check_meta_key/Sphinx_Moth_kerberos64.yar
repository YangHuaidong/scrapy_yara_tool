rule Sphinx_Moth_kerberos64 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-06"
    description = "sphinx moth threat group file kerberos64.dll"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "www.kudelskisecurity.com"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "KERBEROS64.dll" fullword ascii
    $s1 = "zeSecurityDescriptor" fullword ascii
    $s2 = "SpGetInfo" fullword ascii
    $s3 = "SpShutdown" fullword ascii
    $op0 = { 75 05 e8 6a c7 ff ff 48 8b 1d 47 d6 00 00 33 ff } /* Opcode */
    $op1 = { 48 89 05 0c 2b 01 00 c7 05 e2 29 01 00 09 04 00 } /* Opcode */
    $op2 = { 48 8d 3d e3 ee 00 00 ba 58 } /* Opcode */
  condition:
    uint16(0) == 0x5a4d and filesize < 406KB and all of ($s*) and 1 of ($op*)
}