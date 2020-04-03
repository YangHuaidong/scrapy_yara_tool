rule STUXSHOP_config {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    desc = "Stuxshop standalone sample configuration"
    description = "None"
    family = "None"
    hacker = "None"
    hash = "c1961e54d60e34bbec397c9120564e8d08f2f243ae349d2fb20f736510716579"
    judge = "unknown"
    reference = "https://medium.com/chronicle-blog/who-is-gossipgirl-3b4170f846c0"
    threatname = "None"
    threattype = "None"
  strings:
    $cnc1 = "http://211.24.237.226/index.php?data=" ascii wide
    $cnc2 = "http://todaysfutbol.com/index.php?data=" ascii wide
    $cnc3 = "http://78.111.169.146/index.php?data=" ascii wide
    $cnc4 = "http://mypremierfutbol.com/index.php?data=" ascii wide
    $regkey1 = "Software\\Microsoft\\Windows\\CurrentVersion\\MS-DOS Emulation" ascii wide
    $regkey2 = "NTVDMParams" ascii wide
    $flowerOverlap1 = { 85 c0 75 3b 57 ff 75 1c ff 75 18 ff 75 14 50 ff 75 10 ff 75 fc ff 15 }
    $flowerOverlap2 = { 85 c0 75 4c 8b 45 1c 89 45 0c 8d 45 0c 50 8d 45 08 ff 75 18 50 6a 00 ff 75 10 ff 75 20 ff 15 }
    $flowerOverlap3 = { 55 8b ec 53 56 8b 75 20 85 f6 74 03 83 26 00 8d 45 20 50 68 19 00 02 00 6a 00 ff 75 0c ff 75 08 }
    $flowerOverlap4 = { 55 8b ec 51 8d 4d fc 33 c0 51 50 6a 26 50 89 45 fc ff 15 }
    $flowerOverlap5 = { 85 db 74 04 8b c3 eb 1a 8b 45 08 3b 45 14 74 07 b8 5d 06 00 00 eb 0b 85 f6 74 05 8b 45 0c 89 06 }
    $flowerOverlap6 = { 85 ff 74 12 83 7d f8 01 75 0c ff 75 0c ff 75 08 ff 15 }
  condition:
    all of ($flowerOverlap*)
    or
    2 of ($cnc*)
    or
    all of ($regkey*)
}