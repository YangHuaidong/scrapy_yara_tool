rule r57shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file r57shell.php"
    family = "None"
    hacker = "None"
    hash = "8023394542cddf8aee5dec6072ed02b5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"
  condition:
    all of them
}