rule IMPLANT_5_v4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "XTunnel Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $FBKEY1 = { 98 7a b9 99 fe 09 24 a2 df 0a 41 2b 14 e2 60 93 74 6f cd f9 ba 31 dc 05 53 68 92 c3 3b 11 6a d3 }
    $FBKEY2 = { 8b 23 6c 89 2d 90 2b 0c 9a 6d 37 ae 4f 98 42 c3 07 0f bd c1 40 99 c6 93 01 58 56 3c 6a c0 0f f5 }
    $FBKEY3 = { e4 7b 7f 11 0c aa 1d a6 17 54 55 67 ec 97 2a f3 a6 e7 b4 e6 80 7b 79 81 d3 cf bd 3d 8f cc 33 73 }
    $FBKEY4 = { 48 b2 84 54 5c a1 fa 74 f6 4f db e2 e6 05 d6 8c ed 8a 72 6d 05 eb ef d9 ba ac 16 4a 79 49 bd c1 }
    $FBKEY5 = { fb 42 15 58 e3 0f cc d9 5f a7 bc 45 ac 92 d2 99 1c 44 07 22 30 f6 fb ea a2 11 34 1b 5b f2 dc 56 }
  condition:
    all of them
}