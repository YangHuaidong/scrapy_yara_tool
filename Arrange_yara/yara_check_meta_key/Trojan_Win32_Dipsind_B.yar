rule Trojan_Win32_Dipsind_B : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Dipsind Family"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    reference = "None"
    sample_sha1 = "09e0dfbb5543c708c0dd6a89fd22bbb96dc4ca1c"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $frg1 = {8D 90 04 01 00 00 33 C0 F2 AE F7 D1 2B F9 8B C1 8B F7 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 4D EC 8B 15 ?? ?? ?? ?? 89 91 ?? 07 00 00 }
    $frg2 = { 68 a1 86 01 00 c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa }
    $frg3 = { c0 e8 07 d0 e1 0a c1 8a c8 32 d0 c0 e9 07 d0 e0 0a c8 32 ca 80 f1 63 }
  condition:
    $frg1 and $frg2 and $frg3
}