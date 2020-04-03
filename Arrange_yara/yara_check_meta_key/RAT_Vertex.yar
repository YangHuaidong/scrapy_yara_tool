rule RAT_Vertex {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Vertex RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Vertex"
    threatname = "None"
    threattype = "None"
  strings:
    $string1 = "DEFPATH"
    $string2 = "HKNAME"
    $string3 = "HPORT"
    $string4 = "INSTALL"
    $string5 = "IPATH"
    $string6 = "MUTEX"
    $res1 = "PANELPATH"
    $res2 = "ROOTURL"
  condition:
    all of them
}