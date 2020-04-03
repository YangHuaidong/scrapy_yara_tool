rule APT_Project_Sauron_dext_module {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-08"
    description = "Detects strings from dext module - Project Sauron report by Kaspersky"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/eFoP4A"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Assemble rows of DNS names back to a single string of data"
    $x2 = "removes checks of DNS names and lengths (during split)"
    $x3 = "Randomize data lengths (length/2 to length)"
    $x4 = "This cruft"
  condition:
    2 of them
}