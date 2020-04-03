rule WebShell_php_webshells_pws {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file pws.php"
    family = "None"
    hacker = "None"
    hash = "7a405f1c179a84ff8ac09a42177a2bcd8a1a481b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s6 = "if ($_POST['cmd']){" fullword
    $s7 = "$cmd = $_POST['cmd'];" fullword
    $s10 = "echo \"FILE UPLOADED TO $dez\";" fullword
    $s11 = "if (file_exists($uploaded)) {" fullword
    $s12 = "copy($uploaded, $dez);" fullword
    $s17 = "passthru($cmd);" fullword
  condition:
    4 of them
}