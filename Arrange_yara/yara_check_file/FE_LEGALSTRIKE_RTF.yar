rule FE_LEGALSTRIKE_RTF {
   meta:
      version=".1"
      filetype="MACRO"
      author="joshua.kim@FireEye. - modified by Florian Roth"
      date="2017-06-02"
      description="Rtf Phishing Campaign leveraging the CVE 2017-0199 exploit, to point to the domain 2bunnyDOTcom"
   strings:
      $lnkinfo = "4c0069006e006b0049006e0066006f"
      $encoded1 = "4f4c45324c696e6b"
      $encoded2 = "52006f006f007400200045006e007400720079"
      $encoded3 = "4f0062006a0049006e0066006f"
      $encoded4 = "4f006c0065"
      $datastore = "\\*\\datastore"
   condition:
      uint32be(0) == 0x7B5C7274 and all of them
}