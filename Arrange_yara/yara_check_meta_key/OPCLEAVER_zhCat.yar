rule OPCLEAVER_zhCat {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "Network tool used by Iranian hackers and used by attackers in Operation Cleaver"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Mozilla/4.0 ( compatible; MSIE 7.0; AOL 8.0 )" ascii fullword
    $s2 = "ABC ( A Big Company )" wide fullword
  condition:
    all of them
}