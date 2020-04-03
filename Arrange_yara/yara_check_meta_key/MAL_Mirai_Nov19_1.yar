rule MAL_Mirai_Nov19_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-11-13"
    description = "Detects Mirai malware"
    family = "None"
    hacker = "None"
    hash1 = "bbb83da15d4dabd395996ed120435e276a6ddfbadafb9a7f096597c869c6c739"
    hash2 = "fadbbe439f80cc33da0222f01973f27cce9f5ab0709f1bfbf1a954ceac5a579b"
    judge = "black"
    reference = "https://twitter.com/bad_packets/status/1194049104533282816"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "SERVZUXO" fullword ascii
    $s2 = "-loldongs" fullword ascii
    $s3 = "/dev/null" fullword ascii
    $s4 = "/bin/busybox" fullword ascii
    $sc1 = { 47 72 6f 75 70 73 3a 09 30 }
  condition:
    uint16(0) == 0x457f and filesize <= 100KB and 4 of them
}