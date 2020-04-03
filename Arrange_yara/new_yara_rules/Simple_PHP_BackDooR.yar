rule Simple_PHP_BackDooR {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Simple_PHP_BackDooR.php"
    family = "None"
    hacker = "None"
    hash = "a401132363eecc3a1040774bec9cb24f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he"
    $s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn"
    $s9 = "// a simple php backdoor"
  condition:
    1 of them
}