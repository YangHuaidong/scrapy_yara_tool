rule Trojan_Win32_Plainst : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Installer component"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "99c08d31af211a0e17f92dd312ec7ca2b9469ecb"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "dcb6cf7cf7c8fdfc89656a042f81136bda354ba6"
    version = "1.0"
  strings:
    $str1 = { 66 8b 14 4d 18 50 01 10 8b 45 08 66 33 14 70 46 66 89 54 77 fe 66 83 7c 77 fe 00 75 b7 8b 4d fc 89 41 08 8d 04 36 89 41 0c 89 79 04 }
    $str2 = { 4b d3 91 49 a1 80 91 42 83 b6 33 28 36 6b 90 97 }
  condition:
    $str1 and $str2
}