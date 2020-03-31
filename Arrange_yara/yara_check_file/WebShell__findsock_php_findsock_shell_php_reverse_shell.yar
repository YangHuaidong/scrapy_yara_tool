rule WebShell__findsock_php_findsock_shell_php_reverse_shell {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php
    family = php
    hacker = None
    hash0 = 5622c9841d76617bfc3cd4cab1932d8349b7044f
    hash1 = 4a20f36035bbae8e342aab0418134e750b881d05
    hash2 = 40dbdc0bdf5218af50741ba011c5286a723fa9bf
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    super_rule = 1
    threatname = WebShell[]/findsock.php.findsock.shell.php.reverse.shell
    threattype = 
  strings:
    $s1 = "// me at pentestmonkey@pentestmonkey.net" fullword
  condition:
    all of them
}