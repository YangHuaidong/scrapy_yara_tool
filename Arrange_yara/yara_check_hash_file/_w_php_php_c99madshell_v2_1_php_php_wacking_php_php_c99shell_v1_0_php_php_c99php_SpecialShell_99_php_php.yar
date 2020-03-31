rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php {
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
    hash3 = d8ae5819a0a2349ec552cbcf3a62c975
    hash4 = 9e9ae0332ada9c3797d6cee92c2ede62
    hash5 = 09609851caa129e40b0d56e90dfc476c
    judge = unknown
    reference = None
    super_rule = 1
    threatname = [w]/php.php.c99madshell.v2.1.php.php.wacking.php.php.c99shell.v1.0.php.php.c99php.SpecialShell.99.php.php
    threattype = w
  strings:
    $s0 = "$sess_data[\"cut\"] = array(); c99_s"
    $s3 = "if ((!eregi(\"http://\",$uploadurl)) and (!eregi(\"https://\",$uploadurl))"
  condition:
    1 of them
}