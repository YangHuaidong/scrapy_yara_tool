rule webshell_bypass_iisuser_p {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file bypass-iisuser-p.asp"
    family = "None"
    hacker = "None"
    hash = "924d294400a64fa888a79316fb3ccd90"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"
  condition:
    all of them
}