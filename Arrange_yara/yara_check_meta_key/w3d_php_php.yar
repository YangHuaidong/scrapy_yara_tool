rule w3d_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file w3d.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "987f66b29bfb209a0b4f097f84f57c3b"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "W3D Shell"
    $s1 = "By: Warpboy"
    $s2 = "No Query Executed"
  condition:
    2 of them
}