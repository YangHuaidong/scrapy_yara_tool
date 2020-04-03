rule BackDooR__fr_ {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file BackDooR (fr).php"
    family = "None"
    hacker = "None"
    hash = "a79cac2cf86e073a832aaf29a664f4be"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "
  condition:
    all of them
}