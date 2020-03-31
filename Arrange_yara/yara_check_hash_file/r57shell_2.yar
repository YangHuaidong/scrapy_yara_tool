rule r57shell_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file r57shell.php
    family = None
    hacker = None
    hash = 8023394542cddf8aee5dec6072ed02b5
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = r57shell[2
    threattype = 2.yar
  strings:
    $s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_"
  condition:
    all of them
}