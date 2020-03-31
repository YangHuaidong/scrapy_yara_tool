rule StoneDrill_ntssrvr32 {
   meta:
      description = "Detects malware from StoneDrill threat report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07"
      hash1 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
   strings:
      $s1 = "g\\system32\\" fullword wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii
      $op1 = { 94 35 77 73 03 40 eb e9 }
      $op2 = { 80 7c 41 01 00 74 0a 3d }
      $op3 = { 74 0a 3d 00 94 35 77 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and 3 of them )
}