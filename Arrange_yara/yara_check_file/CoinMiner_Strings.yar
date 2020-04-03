rule CoinMiner_Strings {
   meta:
      description = "Detects mining pool protocol string in Executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 50
      reference = "https://minergate.com/faq/what-pool-address"
      date = "2018-01-04"
   strings:
      $s1 = "stratum+tcp://" ascii
      $s2 = "\"normalHashing\": true,"
   condition:
      filesize < 600KB and 1 of them
}