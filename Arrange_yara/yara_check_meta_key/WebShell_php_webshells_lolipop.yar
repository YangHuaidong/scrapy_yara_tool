rule WebShell_php_webshells_lolipop {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file lolipop.php"
    family = "None"
    hacker = "None"
    hash = "86f23baabb90c93465e6851e40104ded5a5164cb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "$commander = $_POST['commander']; " fullword
    $s9 = "$sourcego = $_POST['sourcego']; " fullword
    $s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
  condition:
    all of them
}