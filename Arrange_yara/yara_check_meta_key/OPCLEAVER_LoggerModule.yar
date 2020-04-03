rule OPCLEAVER_LoggerModule {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "Keylogger used by attackers in Operation Cleaver"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%s-%02d%02d%02d%02d%02d.r"
    $s2 = "C:\\Users\\%s\\AppData\\Cookies\\"
  condition:
    all of them
}