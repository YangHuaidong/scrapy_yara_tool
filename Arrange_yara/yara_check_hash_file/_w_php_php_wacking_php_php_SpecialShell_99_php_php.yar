rule _w_php_php_wacking_php_php_SpecialShell_99_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt
    family = php
    hacker = None
    hash0 = 38a3f9f2aa47c2e940695f3dba6a7bb2
    hash1 = 9c5bb5e3a46ec28039e8986324e42792
    hash2 = 09609851caa129e40b0d56e90dfc476c
    judge = unknown
    reference = None
    super_rule = 1
    threatname = [w]/php.php.wacking.php.php.SpecialShell.99.php.php
    threattype = w
  strings:
    $s0 = "\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
    $s2 = "c99sh_sqlquery"
  condition:
    1 of them
}