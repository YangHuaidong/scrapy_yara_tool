rule WebShell_Simple_PHP_backdoor_by_DK {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file Simple_PHP_backdoor_by_DK.php
    family = backdoor
    hacker = None
    hash = 03f6215548ed370bec0332199be7c4f68105274e
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[Simple]/PHP.backdoor.by.DK
    threattype = Simple
  strings:
    $s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
    $s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
    $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
    $s6 = "if(isset($_REQUEST['cmd'])){" fullword
    $s8 = "system($cmd);" fullword
  condition:
    2 of them
}