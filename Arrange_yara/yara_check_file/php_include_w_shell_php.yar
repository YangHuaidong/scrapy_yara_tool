rule php_include_w_shell_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file php-include-w-shell.php.txt
    family = shell
    hacker = None
    hash = 4e913f159e33867be729631a7ca46850
    judge = unknown
    reference = None
    threatname = php[include]/w.shell.php
    threattype = include
  strings:
    $s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd"
    $s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB"
  condition:
    1 of them
}