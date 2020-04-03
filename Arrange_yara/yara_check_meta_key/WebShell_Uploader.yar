rule WebShell_Uploader {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file Uploader.php"
    family = "None"
    hacker = "None"
    hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
  condition:
    all of them
}