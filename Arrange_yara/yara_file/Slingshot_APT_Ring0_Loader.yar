rule Slingshot_APT_Ring0_Loader {
   meta:
      description = "Detects malware from Slingshot APT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
   strings:
      $s1 = " -> Missing element in DataDir -- cannot install" ascii
      $s2 = " -> Primary loader not present in the DataDir" ascii
      $s3 = "\\\\.\\amxpci" fullword ascii
      $s4 = " -> [Goad] ERROR in CreateFile:" fullword ascii
      $s5 = "\\\\.\\Sandra" fullword ascii
      $s6 = " -> [Sandra] RingZeroCode" fullword ascii
      $s7 = " -> [Sandra] Value from IOCTL_RDMSR:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}