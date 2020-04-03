rule MAL_ELF_VPNFilter_1 {
   meta:
      description = "Detects VPNFilter malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24"
      hash1 = "f8286e29faa67ec765ae0244862f6b7914fcdde10423f96595cb84ad5cc6b344"
   strings:
      $s1 = "Login=" fullword ascii
      $s2 = "Password=" fullword ascii
      $s3 = "%s/rep_%u.bin" fullword ascii
      $s4 = "%s:%uh->%s:%hu" fullword ascii
      $s5 = "Password required" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "password=" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "Authorization: Basic" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "/tmUnblock.cgi" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and all of them
}