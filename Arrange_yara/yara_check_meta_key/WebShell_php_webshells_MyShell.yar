rule WebShell_php_webshells_MyShell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file MyShell.php"
    family = "None"
    hacker = "None"
    hash = "42e283c594c4d061f80a18f5ade0717d3fb2f76d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "<title>MyShell error - Access Denied</title>" fullword
    $s4 = "$adminEmail = \"youremail@yourserver.com\";" fullword
    $s5 = "//A workdir has been asked for - we chdir to that dir." fullword
    $s6 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
    $s13 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword
    $s14 = "/* No work_dir - we chdir to $DOCUMENT_ROOT */" fullword
    $s19 = "#every command you excecute." fullword
    $s20 = "<form name=\"shell\" method=\"post\">" fullword
  condition:
    3 of them
}