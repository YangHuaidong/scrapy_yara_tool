rule CoinMiner_Strings {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-04"
    description = "Detects mining pool protocol string in Executable"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://minergate.com/faq/what-pool-address"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "stratum+tcp://" ascii
    $s2 = "\"normalHashing\": true,"
  condition:
    filesize < 600KB and 1 of them
}