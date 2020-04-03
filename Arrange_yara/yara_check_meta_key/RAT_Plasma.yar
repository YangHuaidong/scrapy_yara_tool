rule RAT_Plasma {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Plasma RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Plasma"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "Miner: Failed to Inject." wide
    $b = "Started GPU Mining on:" wide
    $c = "BK: Hard Bot Killer Ran Successfully!" wide
    $d = "Uploaded Keylogs Successfully!" wide
    $e = "No Slowloris Attack is Running!" wide
    $f = "An ARME Attack is Already Running on" wide
    $g = "Proactive Bot Killer Enabled!" wide
    $h = "PlasmaRAT" wide ascii
    $i = "AntiEverything" wide ascii
  condition:
    all of them
}