rule ak74shell_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file ak74shell.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "7f83adcb4c1111653d30c6427a94f66f"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION["
    $s2 = "AK-74 Security Team Web Site: www.ak74-team.net"
    $s3 = "$xshell"
  condition:
    2 of them
}