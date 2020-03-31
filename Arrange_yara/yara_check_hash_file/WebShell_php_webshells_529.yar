rule WebShell_php_webshells_529 {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file 529.php
    family = 529
    hacker = None
    hash = ba3fb2995528307487dff7d5b624d9f4c94c75d3
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[php]/webshells.529
    threattype = php
  strings:
    $s0 = "<p>More: <a href=\"/\">Md5Cracking.Com Crew</a> " fullword
    $s7 = "href=\"/\" title=\"Securityhouse\">Security House - Shell Center - Edited By Kin"
    $s9 = "echo '<PRE><P>This is exploit from <a " fullword
    $s10 = "This Exploit Was Edited By KingDefacer" fullword
    $s13 = "safe_mode and open_basedir Bypass PHP 5.2.9 " fullword
    $s14 = "$hardstyle = explode(\"/\", $file); " fullword
    $s20 = "while($level--) chdir(\"..\"); " fullword
  condition:
    2 of them
}