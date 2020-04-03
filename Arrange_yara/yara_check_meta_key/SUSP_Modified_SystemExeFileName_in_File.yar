rule SUSP_Modified_SystemExeFileName_in_File {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-12-11"
    description = "Detecst a variant of a system file name often used by attackers to cloak their activity"
    family = "None"
    hacker = "None"
    hash1 = "5723f425e0c55c22c6b8bb74afb6b506943012c33b9ec1c928a71307a8c5889a"
    hash2 = "f1f11830b60e6530b680291509ddd9b5a1e5f425550444ec964a08f5f0c1a44e"
    judge = "black"
    reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "svchosts.exe" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}