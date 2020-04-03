rule WebShell_go_shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file go-shell.php"
    family = "None"
    hacker = "None"
    hash = "3dd85981bec33de42c04c53d081c230b5fc0e94f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "#change this password; for power security - delete this file =)" fullword
    $s2 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};" fullword
    $s11 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");" fullword
    $s12 = "print << \"[kalabanga]\";" fullword
    $s13 = "<title>GO.cgi</title>" fullword
  condition:
    1 of them
}