rule _nst_php_php_cybershell_php_php_img_php_php_nstview_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt
    family = php
    hacker = None
    hash0 = ddaf9f1986d17284de83a17fe5f9fd94
    hash1 = ef8828e0bc0641a655de3932199c0527
    hash2 = 17a07bb84e137b8aa60f87cd6bfab748
    hash3 = 4745d510fed4378e4b1730f56f25e569
    judge = unknown
    reference = None
    super_rule = 1
    threatname = [nst]/php.php.cybershell.php.php.img.php.php.nstview.php.php
    threattype = nst
  strings:
    $s0 = "@$rto=$_POST['rto'];" fullword
    $s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword
    $s3 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword
  condition:
    2 of them
}