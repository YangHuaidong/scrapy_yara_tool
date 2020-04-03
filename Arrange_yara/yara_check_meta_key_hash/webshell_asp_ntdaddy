rule webshell_asp_ntdaddy {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ntdaddy.asp"
    family = "None"
    hacker = "None"
    hash = "c5e6baa5d140f73b4e16a6cfde671c68"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s9 = "if  FP  =  \"RefreshFolder\"  or  "
    $s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "
  condition:
    1 of them
}