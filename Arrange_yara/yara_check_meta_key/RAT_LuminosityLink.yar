rule RAT_LuminosityLink {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects LuminosityLink RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/LuminosityLink"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "SMARTLOGS" wide
    $b = "RUNPE" wide
    $c = "b.Resources" wide
    $d = "CLIENTINFO*" wide
    $e = "Invalid Webcam Driver Download URL, or Failed to Download File!" wide
    $f = "Proactive Anti-Malware has been manually activated!" wide
    $g = "REMOVEGUARD" wide
    $h = "C0n1f8" wide
    $i = "Luminosity" wide
    $j = "LuminosityCryptoMiner" wide
    $k = "MANAGER*CLIENTDETAILS*" wide
  condition:
    all of them
}