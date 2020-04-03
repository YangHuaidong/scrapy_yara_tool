rule CGISscan_CGIScan {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file CGIScan.exe"
    family = "None"
    hacker = "None"
    hash = "338820e4e8e7c943074d5a5bc832458a"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Wang Products" fullword wide
    $s2 = "WSocketResolveHost: Cannot convert host address '%s'"
    $s3 = "tcp is the only protocol supported thru socks server"
  condition:
    all of ($s*)
}