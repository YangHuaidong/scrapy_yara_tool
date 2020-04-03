rule Ajax_PHP_Command_Shell_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Ajax_PHP Command Shell.php.txt"
    family = "None"
    hacker = "None"
    hash = "93d1a2e13a3368a2472043bd6331afe9"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>"
    $s2 = "Empty Command..type \\\"shellhelp\\\" for some ehh...help"
    $s3 = "newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct"
  condition:
    1 of them
}