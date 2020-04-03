rule webshell_asp_1d {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 1d.asp"
    family = "None"
    hacker = "None"
    hash = "fad7504ca8a55d4453e552621f81563c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
  condition:
    all of them
}