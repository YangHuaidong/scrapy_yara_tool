rule RAT_NanoCore {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects NanoCore RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/NanoCore"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "NanoCore"
    $b = "ClientPlugin"
    $c = "ProjectData"
    $d = "DESCrypto"
    $e = "KeepAlive"
    $f = "IPNETROW"
    $g = "LogClientMessage"
    $h = "|ClientHost"
    $i = "get_Connected"
    $j = "#=q"
    $key = { 43 6f 24 cb 95 30 38 39 }
  condition:
    6 of them
}