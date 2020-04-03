rule hatman_injector : hatman {
    meta:
        description = "Detects Hatman malware"
        reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
        date = "2017/12/19"
        author = "DHS/NCCIC/ICS-CERT"
    condition:
        ( hatman_memcpy and hatman_origaddr and hatman_loadoff ) and not ( hatman_origcode and hatman_mftmsr )
}