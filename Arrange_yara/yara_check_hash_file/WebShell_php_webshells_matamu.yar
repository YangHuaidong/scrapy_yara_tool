rule WebShell_php_webshells_matamu {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file matamu.php
    family = matamu
    hacker = None
    hash = d477aae6bd2f288b578dbf05c1c46b3aaa474733
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[php]/webshells.matamu
    threattype = php
  strings:
    $s2 = "$command .= ' -F';" fullword
    $s3 = "/* We try and match a cd command. */" fullword
    $s4 = "directory... Trust me - it works :-) */" fullword
    $s5 = "$command .= \" 1> $tmpfile 2>&1; \" ." fullword
    $s10 = "$new_dir = $regs[1]; // 'cd /something/...'" fullword
    $s16 = "/* The last / in work_dir were the first charecter." fullword
  condition:
    2 of them
}