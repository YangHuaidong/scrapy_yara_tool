rule RAT_Adzok {
  meta:
    Versions = "Free 1.0.0.3,"
    author = "Spider"
    comment = "None"
    date = "01.05.2015"
    description = "Detects Adzok RAT"
    family = "None"
    filetype = "jar"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Adzok"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "config.xmlPK"
    $a2 = "key.classPK"
    $a3 = "svd$1.classPK"
    $a4 = "svd$2.classPK"
    $a5 = "Mensaje.classPK"
    $a6 = "inic$ShutdownHook.class"
    $a7 = "Uninstall.jarPK"
    $a8 = "resources/icono.pngPK"
  condition:
    7 of ($a*)
}