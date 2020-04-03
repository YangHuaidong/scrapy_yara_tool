rule RAT_Bozok {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Bozok RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Bozok"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "getVer" nocase
    $b = "StartVNC" nocase
    $c = "SendCamList" nocase
    $d = "untPlugin" nocase
    $e = "gethostbyname" nocase
  condition:
    all of them
}