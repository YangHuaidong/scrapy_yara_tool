rule MAL_ELF_VPNFilter_2 {
   meta:
      description = "Detects VPNFilter malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24"
      hash1 = "50ac4fcd3fbc8abcaa766449841b3a0a684b3e217fc40935f1ac22c34c58a9ec"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0)" fullword ascii
      $s2 = "passwordPASSWORDpassword" fullword ascii
      $s3 = "/tmp/client.key" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 1000KB and all of them
}