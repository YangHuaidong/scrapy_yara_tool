rule WebShell_WinX_Shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file WinX Shell.php"
    family = "None"
    hacker = "None"
    hash = "a94d65c168344ad9fa406d219bdf60150c02010e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "// It's simple shell for all Win OS." fullword
    $s5 = "//------- [netstat -an] and [ipconfig] and [tasklist] ------------" fullword
    $s6 = "<html><head><title>-:[GreenwooD]:- WinX Shell</title></head>" fullword
    $s13 = "// Created by greenwood from n57" fullword
    $s20 = " if (is_uploaded_file($userfile)) {" fullword
  condition:
    3 of them
}