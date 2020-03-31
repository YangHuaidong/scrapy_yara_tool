rule MAL_XMR_Miner_May19_1 {
  meta:
    author = Spider
    comment = None
    date = 2019-05-31
    description = Detects Monero Crypto Coin Miner
    family = May19
    hacker = None
    hash1 = d6df423efb576f167bc28b3c08d10c397007ba323a0de92d1e504a3f490752fc
    judge = unknown
    reference = https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/
    score = 85
    threatname = MAL[XMR]/Miner.May19.1
    threattype = XMR
  strings:
    $x1 = "donate.ssl.xmrig.com" fullword ascii
    $x2 = "* COMMANDS     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
    $s1 = "[%s] login error code: %d" fullword ascii
    $s2 = "\\\\?\\pipe\\uv\\%p-%lu" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 14000KB and (
    pe.imphash() == "25d9618d1e16608cd5d14d8ad6e1f98e" or
    1 of ($x*) or
    2 of them
}