rule OPCLEAVER_csext {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "Backdoor used by attackers in Operation Cleaver"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "COM+ System Extentions"
    $s2 = "csext.exe"
    $s3 = "COM_Extentions_bin"
  condition:
    all of them
}