rule webshell_asp_404 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 404.asp"
    family = "None"
    hacker = "None"
    hash = "d9fa1e8513dbf59fa5d130f389032a2d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"
  condition:
    all of them
}