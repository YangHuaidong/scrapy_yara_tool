rule CN_disclosed_20180208_System3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-08"
    description = "Detects malware from disclosed CN malware set"
    family = "None"
    hacker = "None"
    hash1 = "73fa84cff51d384c2d22d9e53fc5d42cb642172447b07e796c81dd403fb010c2"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/cyberintproject/status/961714165550342146"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "WmiPrvSE.exe" fullword wide
    $s1 = "C:\\Users\\sgl\\AppData\\Local\\" ascii
    $s2 = "Temporary Projects\\WmiPrvSE\\" ascii
    $s3 = "$15a32a5d-4906-458a-8f57-402311afc1c1" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and $a1 and 1 of ($s*)
}