rule webshell_NetworkFileManagerPHP {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file NetworkFileManagerPHP.php"
    family = "None"
    hacker = "None"
    hash = "acdbba993a5a4186fd864c5e4ea0ba4f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
  condition:
    all of them
}