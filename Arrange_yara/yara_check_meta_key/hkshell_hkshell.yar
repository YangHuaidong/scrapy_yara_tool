rule hkshell_hkshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file hkshell.exe"
    family = "None"
    hacker = "None"
    hash = "168cab58cee59dc4706b3be988312580"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "PrSessKERNELU"
    $s2 = "Cur3ntV7sion"
    $s3 = "Explorer8"
  condition:
    all of them
}