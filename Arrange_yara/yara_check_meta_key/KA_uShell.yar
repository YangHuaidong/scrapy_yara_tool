rule KA_uShell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file KA_uShell.php"
    family = "None"
    hacker = "None"
    hash = "685f5d4f7f6751eaefc2695071569aab"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
    $s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"
  condition:
    all of them
}