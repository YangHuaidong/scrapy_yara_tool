rule Trojan_Win32_Placisc4 : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Installer for Dipsind variant"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "3d17828632e8ff1560f6094703ece5433bc69586"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "2abb8e1e9cac24be474e4955c63108ff86d1a034"
    version = "1.0"
  strings:
    $str1 = { 8d 71 01 8b c6 99 bb 0a 00 00 00 f7 fb 0f be d2 0f be 04 39 2b c2 88 04 39 84 c0 74 0a }
    $str2 = { 6a 04 68 00 20 00 00 68 00 00 40 00 6a 00 ff d5 }
    $str3 = {C6 44 24 ?? 64 C6 44 24 ?? 6F C6 44 24 ?? 67 C6 44 24 ?? 32 C6 44 24 ?? 6A}
  condition:
    $str1 and $str2 and $str3
}