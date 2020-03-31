rule Miari_2_May17 {
   meta:
      description = "Detects Mirai Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-12"
      super_rule = 1
      hash1 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
      hash2 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36" fullword ascii
      $s2 = "GET /g.php HTTP/1.1" fullword ascii
      $s3 = "https://%[^/]/%s" fullword ascii
      $s4 = "pass\" value=\"[^\"]*\"" fullword ascii
      $s5 = "jbeupq84v7.2y.net" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 5000KB and 2 of them )
}