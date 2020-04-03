rule SUSP_XORed_Mozilla {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-10-28"
    description = "Detects suspicious XORed keyword - Mozilla/5.0"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "Internal Research"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $xo1 = "Mozilla/5.0" xor ascii wide
    $xof1 = "Mozilla/5.0" ascii wide
  condition:
    $xo1 and not $xof1
}