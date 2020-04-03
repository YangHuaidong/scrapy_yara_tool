rule ms10048_x64 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file ms10048-x64.exe"
    family = "None"
    hacker = "None"
    hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "The target is most likely patched." fullword ascii
    $s2 = "Dojibiron by Ronald Huizer, (c) master#h4cker.us  " fullword ascii
    $s3 = "[ ] Creating evil window" fullword ascii
    $s4 = "[+] Set to %d exploit half succeeded" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 40KB and 1 of them
}