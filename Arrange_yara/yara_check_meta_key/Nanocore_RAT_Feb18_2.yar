rule Nanocore_RAT_Feb18_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-19"
    description = "Detects Nanocore RAT"
    family = "None"
    hacker = "None"
    hash1 = "377ef8febfd8df1a57a7966043ff0c7b8f3973c2cf666136e6c04080bbf9881a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research - T2T"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ResManagerRunnable" fullword ascii
    $s2 = "TransformRunnable" fullword ascii
    $s3 = "MethodInfoRunnable" fullword ascii
    $s4 = "ResRunnable" fullword ascii
    $s5 = "RunRunnable" fullword ascii
    $s6 = "AsmRunnable" fullword ascii
    $s7 = "ReadRunnable" fullword ascii
    $s8 = "ExitRunnable" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}