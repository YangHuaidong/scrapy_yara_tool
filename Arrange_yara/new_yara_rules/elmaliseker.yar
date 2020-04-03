rule elmaliseker {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file elmaliseker.asp"
    family = "None"
    hacker = "None"
    hash = "ccf48af0c8c09bbd038e610a49c9862e"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "javascript:Command('Download'"
    $s5 = "zombie_array=array("
  condition:
    all of them
}