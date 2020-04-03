rule Trojan_Win32_Adupib : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Adupib SSL Backdoor"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
    version = "1.0"
  strings:
    $str1 = "POLL_RATE"
    $str2 = "OP_TIME(end hour)"
    $str3 = "%d:TCP:*:Enabled"
    $str4 = "%s[PwFF_cfg%d]"
    $str5 = "Fake_GetDlgItemTextW: ***value***="
  condition:
    $str1 and $str2 and $str3 and $str4 and $str5
}