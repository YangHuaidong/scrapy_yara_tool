rule multiple_php_webshells_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated "
    family = "None"
    hacker = "None"
    hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
    hash1 = "3ca5886cd54d495dc95793579611f59a"
    hash2 = "9c5bb5e3a46ec28039e8986324e42792"
    hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
    hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
    hash5 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
    hash6 = "09609851caa129e40b0d56e90dfc476c"
    hash7 = "671cad517edd254352fe7e0c7c981c39"
    judge = "black"
    reference = "None"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I"
    $s1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma"
    $s3 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";" fullword
  condition:
    all of them
}