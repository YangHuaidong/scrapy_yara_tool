rule mysql_tool_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file mysql_tool.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "5fbe4d8edeb2769eda5f4add9bab901e"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['"
    $s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV"
    $s4 = "<div align=\"center\">The backup process has now started<br "
  condition:
    1 of them
}