rule Trojan_Win32_Plagon : Platinum {
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
    original_sample_sha1 = "48b89f61d58b57dba6a0ca857bce97bab636af65"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "6dccf88d89ad7b8611b1bc2e9fb8baea41bdb65a"
    version = "1.0"
  strings:
    $str1 = "VPLRXZHTU"
    $str2 = { 64 6f 67 32 6a 7e 6c }
    $str3 = "Dqpqftk(Wou\"Isztk)"
    $str4 = "StartThreadAtWinLogon"
  condition:
    $str1 and $str2 and $str3 and $str4
}