rule loki2crypto {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-21"
    description = "Rule to detect hardcoded DH modulus used in 1996/1997 Loki2 sourcecode; #ifdef STRONG_CRYPTO /* 384-bit strong prime */"
    family = "None"
    hacker = "None"
    hash = "19fbd8cbfb12482e8020a887d6427315"
    hash = "ea06b213d5924de65407e8931b1e4326"
    hash = "14ecd5e6fc8e501037b54ca263896a11"
    hash = "e079ec947d3d4dacb21e993b760a65dc"
    hash = "edf900cebb70c6d1fcab0234062bfc28"
    judge = "black"
    reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $modulus = { da e1 01 cd d8 c9 70 af c2 e4 f2 7a 41 8b 43 39 52 9b 4b 4d e5 85 f8 49 }
  condition:
    (any of them)
}