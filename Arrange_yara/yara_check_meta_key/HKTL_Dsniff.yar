rule HKTL_Dsniff {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-02-19"
    description = "Detects Dsniff hack tool"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://goo.gl/eFoP4A"
    score = 55
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = ".*account.*|.*acct.*|.*domain.*|.*login.*|.*member.*"
  condition:
    1 of them
}