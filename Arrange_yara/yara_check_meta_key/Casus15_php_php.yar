rule Casus15_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Casus15.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
    $s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
    $s3 = "value='Calistirmak istediginiz "
  condition:
    1 of them
}