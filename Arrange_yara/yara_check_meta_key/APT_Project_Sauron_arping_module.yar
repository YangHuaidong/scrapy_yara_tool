rule APT_Project_Sauron_arping_module {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-08"
    description = "Detects strings from arping module - Project Sauron report by Kaspersky"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/eFoP4A"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Resolve hosts that answer"
    $s2 = "Print only replying Ips"
    $s3 = "Do not display MAC addresses"
  condition:
    all of them
}