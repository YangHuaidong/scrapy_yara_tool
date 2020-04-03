rule OPCLEAVER_pvz_in {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "Parviz tool used by attackers in Operation Cleaver"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "LAST_TIME=00/00/0000:00:00PM$"
    $s2 = "if %%ERRORLEVEL%% == 1 GOTO line"
  condition:
    all of them
}