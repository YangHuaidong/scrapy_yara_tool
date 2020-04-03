rule rdrbs084 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file rdrbs084.exe"
    family = "None"
    hacker = "None"
    hash = "ed30327b255816bdd7590bf891aa0020"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Create mapped port. You have to specify domain when using HTTP type."
    $s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"
  condition:
    all of them
}