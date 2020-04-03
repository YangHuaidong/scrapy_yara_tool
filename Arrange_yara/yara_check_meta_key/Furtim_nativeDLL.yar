rule Furtim_nativeDLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-13"
    description = "Detects Furtim malware - file native.dll"
    family = "None"
    hacker = "None"
    hash1 = "4f39d3e70ed1278d5fa83ed9f148ca92383ec662ac34635f7e56cc42eeaee948"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "MISP 3971"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "FqkVpTvBwTrhPFjfFF6ZQRK44hHl26" fullword ascii
    $op0 = { e0 b3 42 00 c7 84 24 ac } /* Opcode */
    $op1 = { a1 e0 79 44 00 56 ff 90 10 01 00 00 a1 e0 79 44 } /* Opcode */
    $op2 = { bf d0 25 44 00 57 89 4d f0 ff 90 d4 02 00 00 59 } /* Opcode */
  condition:
    uint16(0) == 0x5a4d and filesize < 900KB and $s1 or all of ($op*)
}