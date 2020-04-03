rule Trojan_Win32_Plabit : Platinum {
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
    reference = "None"
    sample_sha1 = "6d1169775a552230302131f9385135d385efd166"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $str1 = { 4b d3 91 49 a1 80 91 42 83 b6 33 28 36 6b 90 97 }
    $str2 = "GetInstanceW"
    $str3 = { 8b d0 83 e2 1f 8a 14 0a 30 14 30 40 3b 44 24 04 72 ee }
  condition:
    $str1 and $str2 and $str3
}