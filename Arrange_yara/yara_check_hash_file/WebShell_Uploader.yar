rule WebShell_Uploader {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file Uploader.php
    family = None
    hacker = None
    hash = e216c5863a23fde8a449c31660fd413d77cce0b7
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[Uploader
    threattype = Uploader.yar
  strings:
    $s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
  condition:
    all of them
}