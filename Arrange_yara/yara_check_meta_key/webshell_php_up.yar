rule webshell_php_up {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file up.php"
    family = "None"
    hacker = "None"
    hash = "7edefb8bd0876c41906f4b39b52cd0ef"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
    $s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
    $s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
  condition:
    2 of them
}