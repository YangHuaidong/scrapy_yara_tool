rule zacosmall_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file zacosmall.php.txt"
    family = "None"
    hacker = "None"
    hash = "5295ee8dc2f5fd416be442548d68f7a6"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "rand(1,99999);$sj98"
    $s1 = "$dump_file.='`'.$rows2[0].'`"
    $s3 = "filename=\\\"dump_{$db_dump}_${table_d"
  condition:
    2 of them
}