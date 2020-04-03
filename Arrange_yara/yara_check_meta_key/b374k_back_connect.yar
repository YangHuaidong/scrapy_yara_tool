rule b374k_back_connect {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-18"
    description = "Detects privilege escalation tool"
    family = "None"
    hacker = "None"
    hash1 = "c8e16f71f90bbaaef27ccaabb226b43762ca6f7e34d7d5585ae0eb2d36a4bae5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Analysis"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "AddAtomACreatePro" fullword ascii
    $s2 = "shutdow" fullword ascii
    $s3 = "/config/i386" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 10KB and all of them )
}