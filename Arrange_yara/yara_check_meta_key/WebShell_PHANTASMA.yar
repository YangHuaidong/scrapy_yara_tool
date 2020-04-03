rule WebShell_PHANTASMA {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file PHANTASMA.php"
    family = "None"
    hacker = "None"
    hash = "cd12d42abf854cd34ff9e93a80d464620af6d75e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s12 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ." fullword
    $s15 = "if ($portscan != \"\") {" fullword
    $s16 = "echo \"<br>Banner: $get <br><br>\";" fullword
    $s20 = "$dono = get_current_user( );" fullword
  condition:
    3 of them
}