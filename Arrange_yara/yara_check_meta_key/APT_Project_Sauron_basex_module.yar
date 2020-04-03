rule APT_Project_Sauron_basex_module {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-08"
    description = "Detects strings from basex module - Project Sauron report by Kaspersky"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/eFoP4A"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "64, 64url, 32, 32url or 16."
    $s2 = "Force decoding when input is invalid/corrupt"
    $s3 = "This cruft"
  condition:
    $x1 or 2 of them
}