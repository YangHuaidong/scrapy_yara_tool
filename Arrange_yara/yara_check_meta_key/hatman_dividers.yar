rule hatman_dividers : hatman {
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
    $div1 = { 9a 78 56 00 }
    $div2 = { 34 12 00 00 }
  condition:
    $div1 and $div2
}