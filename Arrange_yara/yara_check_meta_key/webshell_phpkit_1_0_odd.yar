rule webshell_phpkit_1_0_odd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file odd.php"
    family = "None"
    hacker = "None"
    hash = "594d1b1311bbef38a0eb3d6cbb1ab538"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "include('php://input');" fullword
    $s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
    $s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
  condition:
    all of them
}