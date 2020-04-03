rule webshell_Crystal_Crystal {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Crystal.php"
    family = "None"
    hacker = "None"
    hash = "fdbf54d5bf3264eb1c4bff1fac548879"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value"
    $s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f"
  condition:
    all of them
}