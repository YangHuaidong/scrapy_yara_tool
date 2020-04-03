rule OPCLEAVER_pvz_out {
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
    $s1 = "Network Connectivity Module" wide
    $s2 = "OSPPSVC" wide
  condition:
    all of them
}