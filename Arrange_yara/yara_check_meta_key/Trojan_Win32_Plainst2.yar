rule Trojan_Win32_Plainst2 : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Zc tool"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "3f2ce812c38ff5ac3d813394291a5867e2cddcf2"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "88ff852b1b8077ad5a19cc438afb2402462fbd1a"
    version = "1.0"
  strings:
    $str1 = "Connected [%s:%d]..."
    $str2 = "reuse possible: %c"
    $str3 = "] => %d%%\x0a"
  condition:
    $str1 and $str2 and $str3
}