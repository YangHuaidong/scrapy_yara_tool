rule RAT_LuxNet {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects LuxNet RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/LuxNet"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "GetHashCode"
    $b = "Activator"
    $c = "WebClient"
    $d = "op_Equality"
    $e = "dickcursor.cur" wide
    $f = "{0}|{1}|{2}" wide
  condition:
    all of them
}