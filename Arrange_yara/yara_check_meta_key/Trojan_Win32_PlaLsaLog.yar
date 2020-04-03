rule Trojan_Win32_PlaLsaLog : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Loader / possible incomplete LSA Password Filter"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "fa087986697e4117c394c9a58cb9f316b2d9f7d8"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "29cb81dbe491143b2f8b67beaeae6557d8944ab4"
    version = "1.0"
  strings:
    $str1 = { 8a 1c 01 32 da 88 1c 01 8b 74 24 0c 41 3b ce 7c ef 5b 5f c6 04 01 00 5e 81 c4 04 01 00 00 c3 }
    $str2 = "PasswordChangeNotify"
  condition:
    $str1 and $str2
}