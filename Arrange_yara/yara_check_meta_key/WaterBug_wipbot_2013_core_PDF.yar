rule WaterBug_wipbot_2013_core_PDF {
  meta:
    author = "Spider"
    comment = "None"
    date = "22.01.2015"
    description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 core PDF"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://t.co/rF35OaAXrl"
    threatname = "None"
    threattype = "None"
  strings:
    $a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/
    $b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/
  condition:
    uint32(0) == 0x46445025 and #a > 150 and #b > 200
}