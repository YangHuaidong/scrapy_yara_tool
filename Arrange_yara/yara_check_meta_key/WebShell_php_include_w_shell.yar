rule WebShell_php_include_w_shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file php-include-w-shell.php"
    family = "None"
    hacker = "None"
    hash = "1a7f4868691410830ad954360950e37c582b0292"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
    $s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
    $s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword
  condition:
    1 of them
}