rule OPCLEAVER_Parviz_Developer {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "Parviz developer known from Operation Cleaver"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Users\\parviz\\documents\\" nocase
  condition:
    $s1
}