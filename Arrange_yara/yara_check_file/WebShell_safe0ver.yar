rule WebShell_safe0ver {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file safe0ver.php
    family = None
    hacker = None
    hash = 366639526d92bd38ff7218b8539ac0f154190eb8
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[safe0ver
    threattype = safe0ver.yar
  strings:
    $s3 = "$scriptident = \"$scriptTitle By Evilc0der.com\";" fullword
    $s4 = "while (file_exists(\"$lastdir/newfile$i.txt\"))" fullword
    $s5 = "else { /* <!-- Then it must be a File... --> */" fullword
    $s7 = "$contents .= htmlentities( $line ) ;" fullword
    $s8 = "<br><p><br>Safe Mode ByPAss<p><form method=\"POST\">" fullword
    $s14 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
    $s20 = "/* <!-- End of Actions --> */" fullword
  condition:
    3 of them
}