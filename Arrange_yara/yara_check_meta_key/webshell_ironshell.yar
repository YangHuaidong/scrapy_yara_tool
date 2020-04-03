rule webshell_ironshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ironshell.php"
    family = "None"
    hacker = "None"
    hash = "8bfa2eeb8a3ff6afc619258e39fded56"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\""
    $s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di"
  condition:
    all of them
}