rule webshell_cihshell_fix {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cihshell_fix.php"
    family = "None"
    hacker = "None"
    hash = "3823ac218032549b86ee7c26f10c4cb5"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty"
    $s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos"
  condition:
    1 of them
}