rule XMRIG_Monero_Miner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-04"
    description = "Detects Monero mining software"
    family = "None"
    hacker = "None"
    hash1 = "5c13a274adb9590249546495446bb6be5f2a08f9dcd2fc8a2049d9dc471135c0"
    hash2 = "08b55f9b7dafc53dfc43f7f70cdd7048d231767745b76dc4474370fb323d7ae7"
    hash3 = "f3f2703a7959183b010d808521b531559650f6f347a5830e47f8e3831b10bad5"
    hash4 = "0972ea3a41655968f063c91a6dbd31788b20e64ff272b27961d12c681e40b2d2"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/xmrig/xmrig/releases"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
    $s2 = "--cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
    $s3 = "-p, --pass=PASSWORD      password for mining server" fullword ascii
    $s4 = "* VERSIONS:     XMRig/%s libuv/%s%s" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 3000KB and 1 of them
}