rule RAT_DarkComet {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects DarkComet RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/DarkComet"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "#BOT#URLUpdate"
    $a2 = "Command successfully executed!"
    $a3 = "MUTEXNAME" wide
    $a4 = "NETDATA" wide
    $b1 = "FastMM Borland Edition"
    $b2 = "%s, ClassID: %s"
    $b3 = "I wasn't able to open the hosts file"
    $b4 = "#BOT#VisitUrl"
    $b5 = "#KCMDDC"
  condition:
    all of ($a*) or all of ($b*)
}