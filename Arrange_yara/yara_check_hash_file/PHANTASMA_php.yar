rule PHANTASMA_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file PHANTASMA.php.txt
    family = None
    hacker = None
    hash = 52779a27fa377ae404761a7ce76a5da7
    judge = unknown
    reference = None
    threatname = PHANTASMA[php
    threattype = php.yar
  strings:
    $s0 = ">[*] Safemode Mode Run</DIV>"
    $s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>"
    $s2 = "[*] Spawning Shell"
    $s3 = "Cha0s"
  condition:
    2 of them
}