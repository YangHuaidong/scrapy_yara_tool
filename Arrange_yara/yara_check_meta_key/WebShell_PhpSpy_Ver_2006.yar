rule WebShell_PhpSpy_Ver_2006 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
    family = "None"
    hacker = "None"
    hash = "34a89e0ab896c3518d9a474b71ee636ca595625d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "var_dump(@$shell->RegRead($_POST['readregname']));" fullword
    $s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
    $s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32"
    $s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'"
  condition:
    1 of them
}