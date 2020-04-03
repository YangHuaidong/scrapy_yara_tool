rule DeepPanda_sl_txt_packed {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/02/08"
    description = "Hack Deep Panda - ScanLine sl-txt-packed"
    family = "None"
    hacker = "None"
    hash = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Command line port scanner" fullword wide
    $s1 = "sl.exe" fullword wide
    $s2 = "CPports.txt" fullword ascii
    $s3 = ",GET / HTTP/.}" fullword ascii
    $s4 = "Foundstone Inc." fullword wide
    $s9 = " 2002 Foundstone Inc." fullword wide
    $s15 = ", Inc. 2002" fullword ascii
    $s20 = "ICMP Time" fullword ascii
  condition:
    all of them
}