rule WaterBug_sav {
  meta:
    author = "Spider"
    comment = "None"
    date = "22.01.2015"
    description = "Symantec Waterbug Attack - SAV Malware"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://t.co/rF35OaAXrl"
    threatname = "None"
    threattype = "None"
  strings:
    $mz = "MZ"
    $code1a = { 8b 75 18 31 34 81 40 3b c2 72 f5 33 f6 39 7d 14 76 1b 8a 04 0e 88 04 0f 6a 0f 33 d2 8b c7 5b f7 f3 85 d2 75 01 }
    $code1b = { 8b 45 f8 40 89 45 f8 8b 45 10 c1 e8 02 39 45 f8 73 17 8b 45 f8 8b 4d f4 8b 04 81 33 45 20 8b 4d f8 8b 55 f4 89 04 8a eb d7 83 65 f8 00 83 65 ec 00 eb 0e 8b 45 f8 40 89 45 f8 8b 45 ec 40 89 45 ec 8b 45 ec 3b 45 10 73 27 8b 45 f4 03 45 f8 8b 4d f4 03 4d ec 8a 09 88 08 8b 45 f8 33 d2 6a 0f 59 f7 f1 85 d2 75 07 }
    $code1c = { 8a 04 0f 88 04 0e 6a 0f 33 d2 8b c6 5b f7 f3 85 d2 75 01 47 8b 45 14 46 47 3b f8 72 e3 eb 04 c6 04 08 00 48 3b c6 73 f7 33 c0 c1 ee 02 74 0b 8b 55 18 31 14 81 40 3b c6 72 f5 }
    $code2 = { 29 5d 0c 8b d1 c1 ea 05 2b ca 8b 55 f4 2b c3 3d 00 00 00 01 89 0f 8b 4d 10 8d 94 91 00 03 00 00 73 17 8b 7d f8 8b 4d 0c 0f b6 3f c1 e1 08 0b cf c1 e0 08 ff 45 f8 89 4d 0c 8b 0a 8b f8 c1 ef 0b }
  condition:
    ($mz at 0) and (($code1a or $code1b or $code1c) and $code2)
}