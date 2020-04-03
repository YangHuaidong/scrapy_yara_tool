rule RAT_CyberGate {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects CyberGate RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/CyberGate"
    threatname = "None"
    threattype = "None"
  strings:
    $string1 = { 23 23 23 23 40 23 23 23 23 e8 ee e9 f9 23 23 23 23 40 23 23 23 23 }
    $string2 = { 23 23 23 23 40 23 23 23 23 fa fd f0 ef f9 23 23 23 23 40 23 23 23 23 }
    $string3 = "EditSvr"
    $string4 = "TLoader"
    $string5 = "Stroks"
    $string6 = "####@####"
    $res1 = "XX-XX-XX-XX"
    $res2 = "CG-CG-CG-CG"
  condition:
    all of ($string*) and any of ($res*)
}