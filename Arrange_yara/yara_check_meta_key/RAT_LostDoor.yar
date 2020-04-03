rule RAT_LostDoor {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects LostDoor RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/LostDoor"
    threatname = "None"
    threattype = "None"
  strings:
    $a0 = { 0d 0a 2a 45 44 49 54 5f 53 45 52 56 45 52 2a 0d 0a }
    $a1 = "*mlt* = %"
    $a2 = "*ip* = %"
    $a3 = "*victimo* = %"
    $a4 = "*name* = %"
    $b5 = "[START]"
    $b6 = "[DATA]"
    $b7 = "We Control Your Digital World" wide ascii
    $b8 = "RC4Initialize" wide ascii
    $b9 = "RC4Decrypt" wide ascii
  condition:
    all of ($a*) or all of ($b*)
}