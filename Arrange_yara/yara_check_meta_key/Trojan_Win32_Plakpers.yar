rule Trojan_Win32_Plakpers : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Injector / loader component"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "fa083d744d278c6f4865f095cfd2feabee558056"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "3a678b5c9c46b5b87bfcb18306ed50fadfc6372e"
    version = "1.0"
  strings:
    $str1 = "MyFileMappingObject"
    $str2 = "[%.3u]  %s  %s  %s [%s:" wide
    $str3 = "%s\\{%s}\\%s" wide
  condition:
    $str1 and $str2 and $str3
}