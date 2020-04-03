rule Trojan_Win32_Plapiio : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "JPin backdoor"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "3119de80088c52bd8097394092847cd984606c88"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "3acb8fe2a5eb3478b4553907a571b6614eb5455c"
    version = "1.0"
  strings:
    $str1 = "ServiceMain"
    $str2 = "Startup"
    $str3 = {C6 45 ?? 68 C6 45 ?? 4D C6 45 ?? 53 C6 45 ?? 56 C6 45 ?? 6D C6 45 ?? 6D}
  condition:
    $str1 and $str2 and $str3
}