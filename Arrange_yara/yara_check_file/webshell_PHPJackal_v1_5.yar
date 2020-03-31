rule webshell_PHPJackal_v1_5 {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file PHPJackal v1.5.php
    family = 5
    hacker = None
    hash = d76dc20a4017191216a0315b7286056f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[PHPJackal]/v1.5
    threattype = PHPJackal
  strings:
    $s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form"
    $s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr"
  condition:
    all of them
}