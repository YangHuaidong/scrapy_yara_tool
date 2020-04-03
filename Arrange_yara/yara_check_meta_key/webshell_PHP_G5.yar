rule webshell_PHP_G5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file G5.php"
    family = "None"
    hacker = "None"
    hash = "95b4a56140a650c74ed2ec36f08d757f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"
  condition:
    all of them
}