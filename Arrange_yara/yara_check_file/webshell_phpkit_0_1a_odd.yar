rule webshell_phpkit_0_1a_odd {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file odd.php
    family = 1a
    hacker = None
    hash = 3c30399e7480c09276f412271f60ed01
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[phpkit]/0.1a.odd
    threattype = phpkit
  strings:
    $s1 = "include('php://input');" fullword
    $s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
    $s4 = "// uses include('php://input') to execute arbritary code" fullword
    $s5 = "// php://input based backdoor" fullword
  condition:
    2 of them
}