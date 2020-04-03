rule RAT_Infinity {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Infinity RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Infinity"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "CRYPTPROTECT_PROMPTSTRUCT"
    $b = "discomouse"
    $c = "GetDeepInfo"
    $d = "AES_Encrypt"
    $e = "StartUDPFlood"
    $f = "BATScripting" wide
    $g = "FBqINhRdpgnqATxJ.html" wide
    $i = "magic_key" wide
  condition:
    all of them
}