rule RAT_Arcom {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Arcom RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Arcom"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "CVu3388fnek3W(3ij3fkp0930di"
    $a2 = "ZINGAWI2"
    $a3 = "clWebLightGoldenrodYellow"
    $a4 = "Ancestor for '%s' not found" wide
    $a5 = "Control-C hit" wide
    $a6 = { a3 24 25 21 }
  condition:
    all of them
}