rule APT_Project_Sauron_kblogi_module {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-08"
    description = "Detects strings from kblogi module - Project Sauron report by Kaspersky"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/eFoP4A"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Inject using process name or pid. Default"
    $s2 = "Convert mode: Read log from file and convert to text"
    $s3 = "Maximum running time in seconds"
  condition:
    $x1 or 2 of them
}