rule WebShell_php_webshells_README {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file README.md"
    family = "None"
    hacker = "None"
    hash = "ef2c567b4782c994db48de0168deb29c812f7204"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
    $s1 = "php-webshells" fullword
  condition:
    all of them
}