rule WebShell_Generic_PHP_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
    family = "None"
    hacker = "None"
    hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
    hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
    hash2 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
    hash3 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "if((isset($_POST['fileto']))||(isset($_POST['filefrom'])))" fullword
    $s4 = "\\$port = {$_POST['port']};" fullword
    $s5 = "$_POST['installpath'] = \"temp.pl\";}" fullword
    $s14 = "if(isset($_POST['post']) and $_POST['post'] == \"yes\" and @$HTTP_POST_FILES[\"u"
    $s16 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"]"
  condition:
    4 of them
}