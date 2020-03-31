rule webshell_webshells_new_php5 {
  meta:
    author = Spider
    comment = None
    date = 2014/03/28
    description = Web shells - generated from file php5.php
    family = php5
    hacker = None
    hash = cf2ab009cbd2576a806bfefb74906fdf
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[webshells]/new.php5
    threattype = webshells
  strings:
    $s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u"
  condition:
    all of them
}