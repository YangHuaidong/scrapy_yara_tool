rule webshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file webshell.php"
    family = "None"
    hacker = "None"
    hash = "f2f8c02921f29368234bfb4d4622ad19"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "RhViRYOzz"
    $s1 = "d\\O!jWW"
    $s2 = "bc!jWW"
    $s3 = "0W[&{l"
    $s4 = "[INhQ@\\"
  condition:
    all of them
}