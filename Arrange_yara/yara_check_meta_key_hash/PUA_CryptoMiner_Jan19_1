rule PUA_CryptoMiner_Jan19_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-01-31"
    description = "Detects Crypto Miner strings"
    family = "None"
    hacker = "None"
    hash1 = "ede858683267c61e710e367993f5e589fcb4b4b57b09d023a67ea63084c54a05"
    judge = "unknown"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Stratum notify: invalid Merkle branch" fullword ascii
    $s2 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
    $s3 = "User-Agent: cpuminer/" ascii
    $s4 = "hash > target (false positive)" fullword ascii
    $s5 = "thread %d: %lu hashes, %s khash/s" fullword ascii
  condition:
    filesize < 1000KB and 1 of them
}