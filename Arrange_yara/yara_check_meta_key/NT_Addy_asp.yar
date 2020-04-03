rule NT_Addy_asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file NT Addy.asp.txt"
    family = "None"
    hacker = "None"
    hash = "2e0d1bae844c9a8e6e351297d77a1fec"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
    $s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
    $s4 = "RAW D.O.S. COMMAND INTERFACE"
  condition:
    1 of them
}