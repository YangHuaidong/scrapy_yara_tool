rule bdcli100 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file bdcli100.exe"
    family = "None"
    hacker = "None"
    hash = "b12163ac53789fb4f62e4f17a8c2e028"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "unable to connect to "
    $s8 = "backdoor is corrupted on "
  condition:
    all of them
}