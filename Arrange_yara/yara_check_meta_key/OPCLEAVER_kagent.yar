rule OPCLEAVER_kagent {
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
    $s1 = "kill command is in last machine, going back"
    $s2 = "message data length in B64: %d Bytes"
  condition:
    all of them
}