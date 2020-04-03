rule OPCLEAVER_SmartCopy2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "Malware or hack tool used by attackers in Operation Cleaver"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "SmartCopy2.Properties"
    $s2 = "ZhuFrameWork"
  condition:
    all of them
}