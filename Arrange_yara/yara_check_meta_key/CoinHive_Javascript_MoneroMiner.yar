rule CoinHive_Javascript_MoneroMiner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-04"
    description = "Detects CoinHive - JavaScript Crypto Miner"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://coinhive.com/documentation/miner"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii
  condition:
    filesize < 65KB and 1 of them
}