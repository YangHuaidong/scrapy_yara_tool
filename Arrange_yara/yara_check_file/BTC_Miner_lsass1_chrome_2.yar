rule BTC_Miner_lsass1_chrome_2 {
   meta:
      description = "Detects a Bitcoin Miner"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22"
      super_rule = 1
      score = 60
      hash1 = "048e9146387d6ff2ac055eb9ddfbfb9a7f70e95c7db9692e2214fa4bec3d5b2e"
      hash2 = "c8db8469287d47ffdc74fe86ce0e9d6e51de67ba1df318573c9398742116a6e8"
   strings:
      $x1 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $x2 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and 1 of them )
}