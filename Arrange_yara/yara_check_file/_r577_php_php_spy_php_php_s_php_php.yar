rule _r577_php_php_spy_php_php_s_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt
    family = php
    hacker = None
    hash0 = 0714f80f35c1fddef1f8938b8d42a4c8
    hash1 = eed14de3907c9aa2550d95550d1a2d5f
    hash2 = 817671e1bdc85e04cc3440bbd9288800
    judge = unknown
    reference = None
    super_rule = 1
    threatname = [r577]/php.php.spy.php.php.s.php.php
    threattype = r577
  strings:
    $s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['"
    $s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>"
  condition:
    1 of them
}