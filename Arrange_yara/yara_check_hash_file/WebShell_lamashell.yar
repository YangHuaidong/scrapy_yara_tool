rule WebShell_lamashell {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file lamashell.php
    family = None
    hacker = None
    hash = b71181e0d899b2b07bc55aebb27da6706ea1b560
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[lamashell
    threattype = lamashell.yar
  strings:
    $s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
    $s8 = "$curcmd = $_POST['king'];" fullword
    $s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
    $s18 = "<title>lama's'hell v. 3.0</title>" fullword
    $s19 = "_|_  O    _    O  _|_" fullword
    $s20 = "$curcmd = \"ls -lah\";" fullword
  condition:
    2 of them
}