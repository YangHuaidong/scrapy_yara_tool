rule SUSP_CMD_Var_Expansion {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-09-26"
    description = "Detects Office droppers that include a variable expansion string"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/asfakian/status/1044859525675843585"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = " /V:ON" ascii wide fullword
  condition:
    uint16(0) == 0xcfd0 and filesize < 500KB and $a1
}