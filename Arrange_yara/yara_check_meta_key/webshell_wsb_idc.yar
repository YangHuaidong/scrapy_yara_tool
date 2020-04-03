rule webshell_wsb_idc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file idc.php"
    family = "None"
    hacker = "None"
    hash = "7c5b1b30196c51f1accbffb80296395f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
    $s3 = "{eval($_GET['idc']);}" fullword
  condition:
    1 of them
}