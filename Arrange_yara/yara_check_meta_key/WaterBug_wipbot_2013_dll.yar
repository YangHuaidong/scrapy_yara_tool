rule WaterBug_wipbot_2013_dll {
  meta:
    author = "Spider"
    comment = "None"
    date = "22.01.2015"
    description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 Down.dll component"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://t.co/rF35OaAXrl"
    threatname = "None"
    threattype = "None"
  strings:
    $string1 = "/%s?rank=%s"
    $string2 = "ModuleStart\x00ModuleStop\x00start"
    $string3 = "1156fd22-3443-4344-c4ffff"
    $string4 = "read\x20file\x2E\x2E\x2E\x20error\x00\x00"
  condition:
    2 of them
}