rule RAT_ShadowTech {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects ShadowTech RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/ShadowTech"
    threatname = "None"
    threattype = "None"
    type = "file"
  strings:
    $a = "ShadowTech" nocase
    $b = "DownloadContainer"
    $c = "MySettings"
    $d = "System.Configuration"
    $newline = "#-@NewLine@-#" wide
    $split = "pSIL" wide
    $key = "ESIL" wide
  condition:
    4 of them
}