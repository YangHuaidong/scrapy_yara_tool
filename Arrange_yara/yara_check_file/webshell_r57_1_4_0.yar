rule webshell_r57_1_4_0 {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file r57.1.4.0.php
    family = 4
    hacker = None
    hash = 574f3303e131242568b0caf3de42f325
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[r57]/1.4.0
    threattype = r57
  strings:
    $s4 = "@ini_set('error_log',NULL);" fullword
    $s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
    $s7 = "@ini_restore(\"disable_functions\");" fullword
    $s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword
  condition:
    all of them
}