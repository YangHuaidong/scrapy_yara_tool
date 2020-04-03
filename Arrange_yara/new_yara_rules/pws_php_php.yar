rule pws_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file pws.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "ecdc6c20f62f99fa265ec9257b7bf2ce"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
    $s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
    $s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>"
  condition:
    2 of them
}