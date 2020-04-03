rule OPCLEAVER_NetC {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "Net Crawler used by attackers in Operation Cleaver"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "NetC.exe" wide
    $s2 = "Net Service"
  condition:
    all of them
}