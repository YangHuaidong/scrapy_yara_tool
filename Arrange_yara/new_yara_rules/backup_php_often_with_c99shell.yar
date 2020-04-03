rule backup_php_often_with_c99shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file backup.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "aeee3bae226ad57baf4be8745c3f6094"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "#phpMyAdmin MySQL-Dump" fullword
    $s2 = ";db_connect();header('Content-Type: application/octetstr"
    $s4 = "$data .= \"#Database: $database" fullword
  condition:
    all of them
}