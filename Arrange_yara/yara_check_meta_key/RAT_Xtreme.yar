rule RAT_Xtreme {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Xtreme RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Xtreme"
    threatname = "None"
    threattype = "None"
    ver = "2.9, 3.1, 3.2, 3.5"
  strings:
    $a = "XTREME" wide
    $b = "ServerStarted" wide
    $c = "XtremeKeylogger" wide
    $d = "x.html" wide
    $e = "Xtreme RAT" wide
  condition:
    all of them
}