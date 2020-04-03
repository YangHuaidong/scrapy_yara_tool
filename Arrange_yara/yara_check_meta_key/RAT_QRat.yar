rule RAT_QRat {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.08.2015"
    description = "Detects QRAT"
    family = "None"
    filetype = "jar"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com"
    threatname = "None"
    threattype = "None"
  strings:
    $a0 = "e-data"
    $a1 = "quaverse/crypter"
    $a2 = "Qrypt.class"
    $a3 = "Jarizer.class"
    $a4 = "URLConnection.class"
  condition:
    4 of them
}