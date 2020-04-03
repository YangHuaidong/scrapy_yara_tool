rule RAT_Paradox {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Paradox RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Paradox"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "ParadoxRAT"
    $b = "Form1"
    $c = "StartRMCam"
    $d = "Flooders"
    $e = "SlowLaris"
    $f = "SHITEMID"
    $g = "set_Remote_Chat"
  condition:
    all of them
}