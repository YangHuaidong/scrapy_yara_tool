rule DefaceKeeper_0_2_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file DefaceKeeper_0.2.php.txt"
    family = "None"
    hacker = "None"
    hash = "713c54c3da3031bc614a8a55dccd7e7f"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
    $s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9"
    $s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center"
  condition:
    1 of them
}