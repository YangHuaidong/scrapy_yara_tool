rule cmdShell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file cmdShell.asp"
    family = "None"
    hacker = "None"
    hash = "8a9fef43209b5d2d4b81dfbb45182036"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "if cmdPath=\"wscriptShell\" then"
  condition:
    all of them
}