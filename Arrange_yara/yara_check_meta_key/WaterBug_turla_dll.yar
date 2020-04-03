import "pe"
rule WaterBug_turla_dll {
  meta:
    author = "Spider"
    comment = "None"
    date = "22.01.2015"
    description = "Symantec Waterbug Attack - Trojan Turla DLL"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://t.co/rF35OaAXrl"
    threatname = "None"
    threattype = "None"
  strings:
    $a = /([A-Za-z0-9]{2,10}_){,2}Win32\.dll\x00/
  condition:
    pe.exports("ee") and $a
}