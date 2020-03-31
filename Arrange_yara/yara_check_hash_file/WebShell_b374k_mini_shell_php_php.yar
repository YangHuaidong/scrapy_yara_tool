rule WebShell_b374k_mini_shell_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file b374k-mini-shell-php.php.php
    family = shell
    hacker = None
    hash = afb88635fbdd9ebe86b650cc220d3012a8c35143
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[b374k]/mini.shell.php.php
    threattype = b374k
  strings:
    $s0 = "@error_reporting(0);" fullword
    $s2 = "@eval(gzinflate(base64_decode($code)));" fullword
    $s3 = "@set_time_limit(0); " fullword
  condition:
    all of them
}