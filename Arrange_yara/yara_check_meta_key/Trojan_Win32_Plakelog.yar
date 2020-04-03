rule Trojan_Win32_Plakelog : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Raw-input based keylogger"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "3907a9e41df805f912f821a47031164b6636bd04"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "960feeb15a0939ec0b53dcb6815adbf7ac1e7bb2"
    version = "1.0"
  strings:
    $str1 = "<0x02>" wide
    $str2 = "[CTR-BRK]" wide
    $str3 = "[/WIN]" wide
    $str4 = { 8a 16 8a 18 32 da 46 88 18 8b 15 08 e6 42 00 40 41 3b ca 72 eb 5e 5b }
  condition:
    $str1 and $str2 and $str3 and $str4
}