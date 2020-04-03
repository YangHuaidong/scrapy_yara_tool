rule Exp_EPS_CVE20152545 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-19"
    description = "Detects EPS Word Exploit CVE-2015-2545"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research - ME"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "word/media/image1.eps" ascii
    $s2 = "-la;7(la+" ascii
  condition:
    uint16(0) == 0x4b50 and ( $s1 and #s2 > 20 )
}