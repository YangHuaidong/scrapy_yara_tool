rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated 
    family = php
    hacker = None
    hash0 = 38a3f9f2aa47c2e940695f3dba6a7bb2
    hash1 = 3ca5886cd54d495dc95793579611f59a
    hash2 = 9c5bb5e3a46ec28039e8986324e42792
    hash3 = 6cd50a14ea0da0df6a246a60c8f6f9c9
    hash4 = 09609851caa129e40b0d56e90dfc476c
    judge = unknown
    reference = None
    super_rule = 1
    threatname = [w]/php.php.c99madshell.v2.1.php.php.wacking.php.php.SsEs.php.php.SpecialShell.99.php.php
    threattype = w
  strings:
    $s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA"
    $s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec"
  condition:
    1 of them
}