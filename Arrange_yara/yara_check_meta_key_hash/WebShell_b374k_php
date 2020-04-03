rule WebShell_b374k_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file b374k.php.php"
    family = "None"
    hacker = "None"
    hash = "04c99efd187cf29dc4e5603c51be44170987bce2"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
    $s6 = "// password (default is: b374k)"
    $s8 = "//******************************************************************************"
    $s9 = "// b374k 2.2" fullword
    $s10 = "eval(\"?>\".gzinflate(base64_decode("
  condition:
    3 of them
}