rule webshell_Private_i3lue {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Private-i3lue.php"
    family = "None"
    hacker = "None"
    hash = "13f5c7a035ecce5f9f380967cf9d4e92"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s8 = "case 15: $image .= \"\\21\\0\\"
  condition:
    all of them
}