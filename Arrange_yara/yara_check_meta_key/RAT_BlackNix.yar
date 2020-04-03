rule RAT_BlackNix {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects BlackNix RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/BlackNix"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "SETTINGS" wide
    $a2 = "Mark Adler"
    $a3 = "Random-Number-Here"
    $a4 = "RemoteShell"
    $a5 = "SystemInfo"
  condition:
    all of them
}