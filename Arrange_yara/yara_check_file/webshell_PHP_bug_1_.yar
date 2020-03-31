rule webshell_PHP_bug_1_ {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file bug (1).php
    family = 1
    hacker = None
    hash = 91c5fae02ab16d51fc5af9354ac2f015
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[PHP]/bug.1.
    threattype = PHP
  strings:
    $s0 = "@include($_GET['bug']);" fullword
  condition:
    all of them
}