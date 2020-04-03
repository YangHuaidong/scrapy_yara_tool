rule r57shell_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file r57shell.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "d28445de424594a5f14d0fe2a7c4e94f"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = " else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx "
    $s2 = "RusH security team"
    $s3 = "'ru_text12' => 'back-connect"
  condition:
    1 of them
}