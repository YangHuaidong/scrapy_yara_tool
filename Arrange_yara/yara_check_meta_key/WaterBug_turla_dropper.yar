rule WaterBug_turla_dropper {
  meta:
    author = "Spider"
    comment = "None"
    date = "22.01.2015"
    description = "Symantec Waterbug Attack - Trojan Turla Dropper"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://t.co/rF35OaAXrl"
    threatname = "None"
    threattype = "None"
  strings:
    $a = { 0f 31 14 31 20 31 3c 31 85 31 8c 31 a8 31 b1 31 d1 31 8b 32 91 32 b6 32 c4 32 6c 33 ac 33 10 34 }
    $b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}
  condition:
    all of them
}