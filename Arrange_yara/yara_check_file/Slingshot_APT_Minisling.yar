rule Slingshot_APT_Minisling {
   meta:
      description = "Detects malware from Slingshot APT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
   strings:
      $s1 = "{6D29520B-F138-442e-B29F-A4E7140F33DE}" fullword ascii wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}