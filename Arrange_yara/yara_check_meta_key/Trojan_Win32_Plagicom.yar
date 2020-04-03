rule Trojan_Win32_Plagicom : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Installer component"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "99dcb148b053f4cef6df5fa1ec5d33971a58bd1e"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "c1c950bc6a2ad67488e675da4dfc8916831239a7"
    version = "1.0"
  strings:
    $str1 = {C6 44 24 ?? 68 C6 44 24 ?? 4D C6 44 24 ?? 53 C6 44 24 ?? 56 C6 44 24 ??
    00}
    $str2 = "OUEMM/EMM"
    $str3 = { 85 c9 7e 08 fe 0c 10 40 3b c1 7c f8 c3 }
  condition:
    $str1 and $str2 and $str3
}