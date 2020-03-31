rule webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php
    family = 1
    hacker = None
    hash = 089ff24d978aeff2b4b2869f0c7d38a3
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[SimAttacker]/Vrsion.1.0.0.priv8.4.My.friend
    threattype = SimAttacker
  strings:
    $s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo"
    $s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
  condition:
    1 of them
}