rule webshell_caidao_shell_guo {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file guo.php
    family = guo
    hacker = None
    hash = 9e69a8f499c660ee0b4796af14dc08f0
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[caidao]/shell.guo
    threattype = caidao
  strings:
    $s0 = "<?php ($www= $_POST['ice'])!"
    $s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww"
  condition:
    1 of them
}