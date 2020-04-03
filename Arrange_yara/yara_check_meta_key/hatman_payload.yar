rule hatman_payload : hatman {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017/12/19"
    description = "Detects Hatman malware"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
    threatname = "None"
    threattype = "None"
  condition:
    ( hatman_memcpy and hatman_origcode and hatman_mftmsr ) and not ( hatman_origaddr and hatman_loadoff )
}