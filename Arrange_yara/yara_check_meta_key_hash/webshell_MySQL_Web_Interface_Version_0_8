rule webshell_MySQL_Web_Interface_Version_0_8 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file MySQL Web Interface Version 0.8.php"
    family = "None"
    hacker = "None"
    hash = "36d4f34d0a22080f47bb1cb94107c60f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>"
  condition:
    all of them
}