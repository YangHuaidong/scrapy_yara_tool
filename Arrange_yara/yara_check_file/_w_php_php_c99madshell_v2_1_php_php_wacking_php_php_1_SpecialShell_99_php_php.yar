rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_1_SpecialShell_99_php_php {
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
    hash3 = 44542e5c3e9790815c49d5f9beffbbf2
    hash4 = 09609851caa129e40b0d56e90dfc476c
    judge = unknown
    reference = None
    super_rule = 1
    threatname = [w]/php.php.c99madshell.v2.1.php.php.wacking.php.php.1.SpecialShell.99.php.php
    threattype = w
  strings:
    $s0 = "if ($total === FALSE) {$total = 0;}" fullword
    $s1 = "$free_percent = round(100/($total/$free),2);" fullword
    $s2 = "if (!$bool) {$bool = is_dir($letter.\":\\\\\");}" fullword
    $s3 = "$bool = $isdiskette = in_array($letter,$safemode_diskettes);" fullword
  condition:
    2 of them
}