rule MSI {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "None"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $r1 = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 }
  condition:
    uint16(0) == 0xCFD0 and $r1
}