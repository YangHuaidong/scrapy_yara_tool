rule _nst_php_php_img_php_php_nstview_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt
    family = php
    hacker = None
    hash0 = ddaf9f1986d17284de83a17fe5f9fd94
    hash1 = 17a07bb84e137b8aa60f87cd6bfab748
    hash2 = 4745d510fed4378e4b1730f56f25e569
    judge = unknown
    reference = None
    super_rule = 1
    threatname = [nst]/php.php.img.php.php.nstview.php.php
    threattype = nst
  strings:
    $s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i"
    $s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v"
    $s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input"
  condition:
    1 of them
}