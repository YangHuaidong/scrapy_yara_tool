rule OPCLEAVER_Jasus {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/02"
    description = "ARP cache poisoner used by attackers in Operation Cleaver"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "pcap_dump_open"
    $s2 = "Resolving IPs to poison..."
    $s3 = "WARNNING: Gateway IP can not be found"
  condition:
    all of them
}