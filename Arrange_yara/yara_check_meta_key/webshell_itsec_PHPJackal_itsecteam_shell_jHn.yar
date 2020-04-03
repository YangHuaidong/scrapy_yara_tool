rule webshell_itsec_PHPJackal_itsecteam_shell_jHn {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
    family = "None"
    hacker = "None"
    hash0 = "8ae9d2b50dc382f0571cd7492f079836"
    hash1 = "e2830d3286001d1455479849aacbbb38"
    hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
    hash3 = "40c6ecf77253e805ace85f119fe1cebb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");" fullword
    $s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|"
    $s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+"
  condition:
    2 of them
}