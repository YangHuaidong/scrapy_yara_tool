rule CVE_2017_8759_SOAP_Excel {
  meta:
    author = Spider
    comment = None
    date = 2017-09-15
    description = Detects malicious files related to CVE-2017-8759
    family = SOAP
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://twitter.com/buffaloverflow/status/908455053345869825
    score = 60
    threatname = CVE[2017]/8759.SOAP.Excel
    threattype = 2017
  strings:
    $s1 = "|'soap:wsdl=" ascii wide nocase
  condition:
    ( filesize < 300KB and 1 of them )
}