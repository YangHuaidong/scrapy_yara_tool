rule Trojan_Win32_Plakpeer : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Zc tool v2"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "2155c20483528377b5e3fde004bb604198463d29"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "dc991ef598825daabd9e70bac92c79154363bab2"
    version = "1.0"
  strings:
    $str1 = "@@E0020(%d)" wide
    $str2 = /exit.{0,3}@exit.{0,3}new.{0,3}query.{0,3}rcz.{0,3}scz/ wide
    $str3 = "---###---" wide
    $str4 = "---@@@---" wide
  condition:
    $str1 and $str2 and $str3 and $str4
}