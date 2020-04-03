rule RAT_JavaDropper {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.10.2015"
    description = "Detects JavaDropper RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/JavaDropper"
    threatname = "None"
    threattype = "None"
  strings:
    $jar = "META-INF/MANIFEST.MF"
    $b1 = "config.ini"
    $b2 = "password.ini"
    $c1 = "stub/stub.dll"
  condition:
    $jar and (all of ($b*) or all of ($c*))
}