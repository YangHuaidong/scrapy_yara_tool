rule webshell_zacosmall {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file zacosmall.php
    family = None
    hacker = None
    hash = 5295ee8dc2f5fd416be442548d68f7a6
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[zacosmall
    threattype = zacosmall.yar
  strings:
    $s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"
  condition:
    all of them
}