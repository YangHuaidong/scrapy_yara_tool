rule webshell_asp_shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file shell.asp"
    family = "None"
    hacker = "None"
    hash = "e63f5a96570e1faf4c7b8ca6df750237"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
    $s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
  condition:
    all of them
}