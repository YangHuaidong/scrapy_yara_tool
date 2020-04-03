rule APT_Project_Sauron_Custom_M1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-09"
    description = "Detects malware from Project Sauron APT"
    family = "None"
    hacker = "None"
    hash1 = "9572624b6026311a0e122835bcd7200eca396802000d0777dba118afaaf9f2a9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/eFoP4A"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ncnfloc.dll" fullword wide
    $s4 = "Network Configuration Locator" fullword wide
    $op0 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 } /* Opcode */
    $op1 = { 80 75 29 85 c9 79 25 b9 01 } /* Opcode */
    $op2 = { 2b d8 48 89 7c 24 38 44 89 6c 24 40 83 c3 08 89 } /* Opcode */
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and ( all of ($s*) ) and 1 of ($op*) ) or ( all of them )
}