rule RAT_Ap0calypse {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Ap0calypse RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Ap0calypse"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "Ap0calypse"
    $b = "Sifre"
    $c = "MsgGoster"
    $d = "Baslik"
    $e = "Dosyalars"
    $f = "Injecsiyon"
  condition:
    all of them
}