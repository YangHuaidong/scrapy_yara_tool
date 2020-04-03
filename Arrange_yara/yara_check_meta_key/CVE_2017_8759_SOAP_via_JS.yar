rule CVE_2017_8759_SOAP_via_JS {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-14"
    description = "Detects SOAP WDSL Download via JavaScript"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/buffaloverflow/status/907728364278087680"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "GetObject(\"soap:wsdl=https://" ascii wide nocase
    $s2 = "GetObject(\"soap:wsdl=http://" ascii wide nocase
  condition:
    ( filesize < 3KB and 1 of them )
}