rule Waterbear_10_Jun17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-23"
    description = "Detects malware from Operation Waterbear"
    family = "None"
    hacker = "None"
    hash1 = "3b1e67e0e86d912d7bc6dee5b0f801260350e8ce831c93c3e9cfe5a39e766f41"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/L9g9eR"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ADVPACK32.DLL" fullword wide
    $s5 = "ADVPACK32" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}