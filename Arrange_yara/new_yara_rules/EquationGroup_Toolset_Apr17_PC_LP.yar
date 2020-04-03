rule EquationGroup_Toolset_Apr17_PC_LP {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "3a505c39acd48a258f4ab7902629e5e2efa8a2120a4148511fe3256c37967296"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "* Failed to get connection information.  Aborting launcher!" fullword wide
    $s2 = "Format: <command> <target port> [lp port]" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}