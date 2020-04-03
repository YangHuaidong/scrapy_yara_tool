rule Trojan_Win32_Placisc2 : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Dipsind variant"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "bf944eb70a382bd77ee5b47548ea9a4969de0527"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "d807648ddecc4572c7b04405f496d25700e0be6e"
    version = "1.0"
  strings:
    $str1 = { 76 16 8b d0 83 e2 07 8a 4c 14 24 8a 14 18 32 d1 88 14 18 40 3b c7 72 ea }
    $str2 = "VPLRXZHTU"
    $str3 = "%d) Command:%s"
    $str4 = { 0d 0a 2d 2d 2d 2d 2d 09 2d 2d 2d 2d 2d 2d 0d 0a }
  condition:
    $str1 and $str2 and $str3 and $str4
}