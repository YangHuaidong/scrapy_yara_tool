rule SetupBDoor {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file SetupBDoor.exe"
    family = "None"
    hacker = "None"
    hash = "41f89e20398368e742eda4a3b45716b6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\BDoor\\SetupBDoor"
  condition:
    all of them
}