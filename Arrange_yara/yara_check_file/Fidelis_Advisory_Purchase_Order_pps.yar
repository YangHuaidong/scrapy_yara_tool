rule Fidelis_Advisory_Purchase_Order_pps {
    meta:
        description = "Detects a string found in a malicious document named Purchase_Order.pps"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://goo.gl/ZjJyti"
        date = "2015-06-09"
    strings:
        $s0 = "Users\\Gozie\\Desktop\\Purchase-Order.gif" ascii
    condition:
        all of them
}