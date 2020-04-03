rule remsec_packer_A {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Symantec"
    date = "2016/08/08"
    description = "Detects malware from Symantec's Strider APT report"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $code = { 69 ( C? | D? | E? | F? ) AB 00 00 00 ( 81 | 41 81 ) C? CD 2B 00 00 ( F7 | 41 F7 ) E? ( C1 | 41 C1 ) E? 0D ( 69 | 45 69 ) ( C? | D? | E? | F? ) 85 CF 00 00 ( 29 | 41 29 | 44 29 | 45 29 | 2B | 41 2B | 44 2B | 45 2B ) }
  condition:
    all of them
}