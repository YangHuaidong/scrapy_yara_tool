rule CVE_2017_8759_SOAP_via_JS {
   meta:
      description = "Detects SOAP WDSL Download via JavaScript"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/907728364278087680"
      date = "2017-09-14"
      score = 60
   strings:
      $s1 = "GetObject(\"soap:wsdl=https://" ascii wide nocase
      $s2 = "GetObject(\"soap:wsdl=http://" ascii wide nocase
   condition:
      ( filesize < 3KB and 1 of them )
}