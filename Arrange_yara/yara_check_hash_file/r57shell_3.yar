rule r57shell_3 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file r57shell.php
    family = None
    hacker = None
    hash = 87995a49f275b6b75abe2521e03ac2c0
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = r57shell[3
    threattype = 3.yar
  strings:
    $s1 = "<b>\".$_POST['cmd']"
  condition:
    all of them
}