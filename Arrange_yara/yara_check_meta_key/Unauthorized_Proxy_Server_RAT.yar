rule Unauthorized_Proxy_Server_RAT {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "None"
    desscription = "Detects Proxy Server RAT"
    family = "None"
    hacker = "None"
    hash1 = "C74E289AD927E81D2A1A56BC73E394AB"
    hash2 = "2950E3741D7AF69E0CA0C5013ABC4209"
    judge = "black"
    reference = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = { 8a 04 31 32 c2 88 04 31 25 ff 00 00 00 03 c2 99 f7 3d 40 40 49 00 a1 44 40 49 00 03 d0 41 3b cf 72 de 5e 5f c3 }
    $s1 = { 8a 04 31 88 44 24 14 32 c2 88 04 31 8b 44 24 14 25 ff 00 00 00 03 c2 99 f7 3d 40 40 49 00 a1 44 40 49 00 03 d0 41 3b cf 72 d6 5e 5f c3 }
    $s2 = { 8a 04 31 88 44 24 14 32 c2 88 04 31 8b 44 24 14 25 ff 00 00 00 03 c2 99 f7 3d 5c 39 41 00 a1 60 39 41 00 03 d0 41 3b cf 72 d6 5e 5f c3 }
    $s3 = { 8a 04 31 32 c2 88 04 31 25 ff 00 00 00 03 c2 99 f7 3d 5c 39 41 00 a1 60 39 41 00 03 d0 41 3b cf 72 de 5e 5f c3 }
    $s4 = { b9 1a 79 00 00 8a 14 07 80 f2 9a 88 10 40 49 75 f4 }
    $s5 = { 39 9f e1 92 76 9f 83 9d ce 9f 2a 9d 2c 9e ad 9c eb 9f d1 9c a5 9f 7e 9f 53 9c ef 9f 02 9f 96 9c 6c 9e 5c 9d 94 9f c9 9f }
    $s6 = { 8a 04 31 88 44 24 14 32 c2 88 04 31 8b 44 24 14 25 ff 00 00 00 03 c2 99 f7 3d 40 60 09 10 a1 44 60 09 10 03 d0 41 3b cf 72 d6 5e 5f c3 }
    $s7 = { 3c 5c 75 20 8a 41 01 41 84 c0 74 18 3c 72 74 0c 3c 74 74 08 3c 62 74 04 3c 22 75 08 8a 41 01 41 84 c0 75 dc }
    $s8 = { 8b 06 3d 95 34 12 00 77 35 3d 59 34 12 00 72 2e 66 8b 46 04 66 3d e8 03 7f 24 }
    $s9 = { 8b c8 8b 74 24 1c c1 e1 05 2b c8 8b 7c 24 18 c1 e1 04 8b 5c 24 14 03 c8 8d 04 88 8b 4c 24 20 83 f9 01 89 44 24 0c 75 23 }
    $s10 = { 8b 06 3d 90 34 12 00 77 35 3d 59 34 12 00 72 2e 66 8b 46 04 66 3d e8 03 7f 24 66 85 c0 }
    $s11 = { 30 11 0f b6 01 48 ff c1 02 c2 0f be c0 99 41 f7 f9 41 03 d2 49 ff c8 75 e7 }
    $s12 = { 44 8b e8 b8 4f ec c4 4e 41 f7 ed c1 fa 03 8b ca c1 e9 1f 03 d1 6b d2 1a 44 2b ea 41 83 c5 41 }
    $s13 = { 8a 0a 80 f9 62 7c 23 80 f9 79 7f 1e 80 f9 64 7c 0a 80 f9 6d 7f 05 80 c1 0b eb 0d 80 f9 6f 7c 0a 80 f9 78 7f 05 }
  condition:
    any of them
}