rule Sincap_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Sincap.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "b68b90ff6012a103e57d141ed38a7ee9"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');"
    $s2 = "$tampon4=$tampon3-1"
    $s3 = "@aventgrup.net"
  condition:
    2 of them
}