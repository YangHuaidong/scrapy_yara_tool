rule WebShell_php_webshells_lostDC {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file lostDC.php"
    family = "None"
    hacker = "None"
    hash = "d54fe07ea53a8929620c50e3a3f8fb69fdeb1cde"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$info .= '[~]Server: ' .$_SERVER['HTTP_HOST'] .'<br />';" fullword
    $s4 = "header ( \"Content-Description: Download manager\" );" fullword
    $s5 = "print \"<center>[ Generation time: \".round(getTime()-startTime,4).\" second"
    $s9 = "if (mkdir($_POST['dir'], 0777) == false) {" fullword
    $s12 = "$ret = shellexec($command);" fullword
  condition:
    2 of them
}