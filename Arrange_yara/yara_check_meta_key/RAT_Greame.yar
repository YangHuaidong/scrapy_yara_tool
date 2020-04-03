rule RAT_Greame {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Greame RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Greame"
    threatname = "None"
    threattype = "None"
  strings:
    $a = { 23 23 23 23 40 23 23 23 23 e8 ee e9 f9 23 23 23 23 40 23 23 23 23 }
    $b = { 23 23 23 23 40 23 23 23 23 fa fd f0 ef f9 23 23 23 23 40 23 23 23 23 }
    $c = "EditSvr"
    $d = "TLoader"
    $e = "Stroks"
    $f = "Avenger by NhT"
    $g = "####@####"
    $h = "GREAME"
  condition:
    all of them
}