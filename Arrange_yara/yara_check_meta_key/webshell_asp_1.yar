rule webshell_asp_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 1.asp"
    family = "None"
    hacker = "None"
    hash = "8991148adf5de3b8322ec5d78cb01bdb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "!22222222222222222222222222222222222222222222222222" fullword
    $s8 = "<%eval request(\"pass\")%>" fullword
  condition:
    all of them
}