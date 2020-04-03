rule Slingshot_APT_Spork_Downloader {
   meta:
      description = "Detects malware from Slingshot APT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
   strings:
      $s1 = "Usage: spork -c IP:PORT" fullword ascii wide
      $s2 = "connect-back IP address and port number"
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}