rule webshell_Mysql_interface_v1_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Mysql interface v1.0.php"
    family = "None"
    hacker = "None"
    hash = "a12fc0a3d31e2f89727b9678148cd487"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"
  condition:
    all of them
}