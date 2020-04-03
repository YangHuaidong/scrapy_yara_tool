rule Trojan_Win32_Plaplex : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Variant of the JPin backdoor"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "ca3bda30a3cdc15afb78e54fa1bbb9300d268d66"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "2fe3c80e98bbb0cf5a0c4da286cd48ec78130a24"
    version = "1.0"
  strings:
    $class_name1 = "AVCObfuscation"
    $class_name2 = "AVCSetiriControl"
  condition:
    $class_name1 and $class_name2
}