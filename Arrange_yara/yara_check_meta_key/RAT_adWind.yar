rule RAT_adWind {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Adwind RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/adWind"
    threatname = "None"
    threattype = "None"
  strings:
    $meta = "META-INF"
    $conf = "config.xml"
    $a = "Adwind.class"
    $b = "Principal.adwind"
  condition:
    all of them
}