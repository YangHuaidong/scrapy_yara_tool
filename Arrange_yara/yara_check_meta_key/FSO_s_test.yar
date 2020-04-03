rule FSO_s_test {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file test.php"
    family = "None"
    hacker = "None"
    hash = "82cf7b48da8286e644f575b039a99c26"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$yazi = \"test\" . \"\\r\\n\";"
    $s2 = "fwrite ($fp, \"$yazi\");"
  condition:
    all of them
}