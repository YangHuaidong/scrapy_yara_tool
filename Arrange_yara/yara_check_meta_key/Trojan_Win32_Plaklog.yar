rule Trojan_Win32_Plaklog : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Hook-based keylogger"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "831a5a29d47ab85ee3216d4e75f18d93641a9819"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "e18750207ddbd939975466a0e01bd84e75327dda"
    version = "1.0"
  strings:
    $str1 = "++[%s^^unknown^^%s]++"
    $str2 = "vtfs43/emm"
    $str3 = { 33 c9 39 4c 24 08 7e 10 8b 44 24 04 03 c1 80 00 08 41 3b 4c 24 08 7c f0 c3 }
  condition:
    $str1 and $str2 and $str3
}