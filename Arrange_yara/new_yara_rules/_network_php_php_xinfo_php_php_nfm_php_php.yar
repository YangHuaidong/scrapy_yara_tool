rule _network_php_php_xinfo_php_php_nfm_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - from files network.php.php.txt, xinfo.php.php.txt, nfm.php.php.txt"
    family = "None"
    hacker = "None"
    hash0 = "acdbba993a5a4186fd864c5e4ea0ba4f"
    hash1 = "2601b6fc1579f263d2f3960ce775df70"
    hash2 = "401fbae5f10283051c39e640b77e4c26"
    judge = "unknown"
    reference = "None"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = ".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa"
    $s2 = "<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''"
  condition:
    all of them
}