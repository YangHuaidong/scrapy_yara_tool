rule SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
    family = "None"
    hacker = "None"
    hash = "089ff24d978aeff2b4b2869f0c7d38a3"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend"
    $s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
    $s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora"
  condition:
    1 of them
}