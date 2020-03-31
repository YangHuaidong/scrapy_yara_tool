rule _r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated 
    family = php
    hacker = None
    hash0 = 0714f80f35c1fddef1f8938b8d42a4c8
    hash1 = 911195a9b7c010f61b66439d9048f400
    hash2 = eddf7a8fde1e50a7f2a817ef7cece24f
    hash3 = 8023394542cddf8aee5dec6072ed02b5
    hash4 = eed14de3907c9aa2550d95550d1a2d5f
    hash5 = 817671e1bdc85e04cc3440bbd9288800
    judge = unknown
    reference = None
    super_rule = 1
    threatname = [r577]/php.php.SnIpEr.SA.Shell.php.r57.php.php.r57.Shell.php.php.spy.php.php.s.php.php
    threattype = r577
  strings:
    $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o"
    $s4 = "if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult"
  condition:
    1 of them
}