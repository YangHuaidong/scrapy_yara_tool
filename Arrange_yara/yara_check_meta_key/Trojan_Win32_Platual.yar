rule Trojan_Win32_Platual : Platinum {
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
    original_sample_sha1 = "e0ac2ae221328313a7eee33e9be0924c46e2beb9"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "ccaf36c2d02c3c5ca24eeeb7b1eae7742a23a86a"
    version = "1.0"
  strings:
    $class_name = "AVCObfuscation"
    $scrambled_dir = { a8 8b b8 e3 b1 d7 fe 85 51 32 3e c0 f1 b7 73 99 }
  condition:
    $class_name and $scrambled_dir
}