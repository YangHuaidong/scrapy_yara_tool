rule webshell_Worse_Linux_Shell {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file Worse Linux Shell.php
    family = Shell
    hacker = None
    hash = 8338c8d9eab10bd38a7116eb534b5fa2
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[Worse]/Linux.Shell
    threattype = Worse
  strings:
    $s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"
  condition:
    all of them
}