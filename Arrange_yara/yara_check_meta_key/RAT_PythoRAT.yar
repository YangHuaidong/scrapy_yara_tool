rule RAT_PythoRAT {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Python RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/PythoRAT"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "TKeylogger"
    $b = "uFileTransfer"
    $c = "TTDownload"
    $d = "SETTINGS"
    $e = "Unknown" wide
    $f = "#@#@#"
    $g = "PluginData"
    $i = "OnPluginMessage"
  condition:
    all of them
}