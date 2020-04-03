rule webshell_tinyasp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-01-09"
    description = "Detects 24 byte ASP webshell and variations"
    family = "None"
    hacker = "None"
    hash1 = "1f29905348e136b66d4ff6c1494d6008ea13f9551ad5aa9b991893a31b37e452"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Execute Request" ascii wide nocase
  condition:
    uint16(0) == 0x253c and filesize < 150 and 1 of them
}