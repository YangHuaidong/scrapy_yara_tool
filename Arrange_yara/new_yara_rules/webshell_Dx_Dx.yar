rule webshell_Dx_Dx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Dx.php"
    family = "None"
    hacker = "None"
    hash = "9cfe372d49fe8bf2fac8e1c534153d9b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
    $s9 = "class=linelisting><nobr>POST (php eval)</td><"
  condition:
    1 of them
}