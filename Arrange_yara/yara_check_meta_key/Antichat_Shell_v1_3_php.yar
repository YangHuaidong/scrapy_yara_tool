rule Antichat_Shell_v1_3_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Antichat Shell v1.3.php.txt"
    family = "None"
    hacker = "None"
    hash = "40d0abceba125868be7f3f990f031521"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Antichat"
    $s1 = "Can't open file, permission denide"
    $s2 = "$ra44"
  condition:
    2 of them
}