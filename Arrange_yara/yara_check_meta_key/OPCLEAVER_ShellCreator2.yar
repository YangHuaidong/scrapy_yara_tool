rule OPCLEAVER_ShellCreator2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "Shell Creator used by attackers in Operation Cleaver to create ASPX web shells"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ShellCreator2.Properties"
    $s2 = "set_IV"
  condition:
    all of them
}