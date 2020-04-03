rule webshell_s72_Shell_v1_1_Coding {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file s72 Shell v1.1 Coding.php"
    family = "None"
    hacker = "None"
    hash = "c2e8346a5515c81797af36e7e4a3828e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "
  condition:
    all of them
}