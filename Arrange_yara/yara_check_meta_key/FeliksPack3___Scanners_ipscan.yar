rule FeliksPack3___Scanners_ipscan {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file ipscan.exe"
    family = "None"
    hacker = "None"
    hash = "6c1bcf0b1297689c8c4c12cc70996a75"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "WCAP;}ECTED"
    $s4 = "NotSupported"
    $s6 = "SCAN.VERSION{_"
  condition:
    all of them
}