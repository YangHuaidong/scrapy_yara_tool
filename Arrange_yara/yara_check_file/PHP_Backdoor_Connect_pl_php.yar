rule PHP_Backdoor_Connect_pl_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file PHP Backdoor Connect.pl.php.txt
    family = pl
    hacker = None
    hash = 57fcd9560dac244aeaf95fd606621900
    judge = unknown
    reference = None
    threatname = PHP[Backdoor]/Connect.pl.php
    threattype = Backdoor
  strings:
    $s0 = "LorD of IRAN HACKERS SABOTAGE"
    $s1 = "LorD-C0d3r-NT"
    $s2 = "echo --==Userinfo==-- ;"
  condition:
    1 of them
}