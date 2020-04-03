rule webshell_webshells_new_radhat {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file radhat.asp"
    family = "None"
    hacker = "None"
    hash = "72cb5ef226834ed791144abaa0acdfd4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "sod=Array(\"D\",\"7\",\"S"
  condition:
    all of them
}