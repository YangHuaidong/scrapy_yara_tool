rule webshell_caidao_shell_404 {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file 404.php
    family = 404
    hacker = None
    hash = ee94952dc53d9a29bdf4ece54c7a7aa7
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[caidao]/shell.404
    threattype = caidao
  strings:
    $s0 = "<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St"
  condition:
    all of them
}