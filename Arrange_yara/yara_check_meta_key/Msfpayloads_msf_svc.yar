rule Msfpayloads_msf_svc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-09"
    description = "Metasploit Payloads - file msf-svc.exe"
    family = "None"
    hacker = "None"
    hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "PAYLOAD:" fullword ascii
    $s2 = ".exehll" ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}