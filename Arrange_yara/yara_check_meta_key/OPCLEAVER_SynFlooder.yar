rule OPCLEAVER_SynFlooder {
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
    $s1 = "Unable to resolve [ %s ]. ErrorCode %d"
    $s2 = "s IP is : %s"
    $s3 = "Raw TCP Socket Created successfully."
  condition:
    all of them
}