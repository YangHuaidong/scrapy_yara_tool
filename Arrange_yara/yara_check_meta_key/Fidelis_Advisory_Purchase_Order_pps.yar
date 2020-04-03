rule Fidelis_Advisory_Purchase_Order_pps {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-09"
    description = "Detects a string found in a malicious document named Purchase_Order.pps"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/ZjJyti"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Users\\Gozie\\Desktop\\Purchase-Order.gif" ascii
  condition:
    all of them
}