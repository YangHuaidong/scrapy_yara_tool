rule PUA_LNX_XMRIG_CryptoMiner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-28"
    description = "Detects XMRIG CryptoMiner software"
    family = "None"
    hacker = "None"
    hash1 = "10a72f9882fc0ca141e39277222a8d33aab7f7a4b524c109506a407cd10d738c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "--multihash-factor=N              number of hash blocks to process at a time (don't set or 0 enables automatic selection o" fullword ascii
    $s2 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume, 'q' shutdown" fullword ascii
    $s3 = "* THREADS:      %d, %s, aes=%d, hf=%zu, %sdonate=%d%%" fullword ascii
    $s4 = ".nicehash.com" fullword ascii
  condition:
    uint16(0) == 0x457f and filesize < 8000KB and ( 1 of ($x*) or 2 of them )
}