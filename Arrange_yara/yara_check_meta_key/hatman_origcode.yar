rule hatman_origcode : hatman {
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
    $ocode_be = { 3c 00 00 03 60 00 a0 b0 7c 09 03 a6 4e 80 04 20 }
    $ocode_le = { 03 00 00 3c b0 a0 00 60 a6 03 09 7c 20 04 80 4e }
  condition:
    $ocode_be or $ocode_le
}