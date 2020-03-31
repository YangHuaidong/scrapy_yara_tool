rule CVE_2017_8759_SOAP_via_JS {
  meta:
    author = Spider
    comment = None
    date = 2017-09-14
    description = Detects SOAP WDSL Download via JavaScript
    family = SOAP
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://twitter.com/buffaloverflow/status/907728364278087680
    score = 60
    threatname = CVE[2017]/8759.SOAP.via.JS
    threattype = 2017
  strings:
    $s1 = "GetObject(\"soap:wsdl=https://" ascii wide nocase
    $s2 = "GetObject(\"soap:wsdl=http://" ascii wide nocase
  condition:
    ( filesize < 3KB and 1 of them )
}