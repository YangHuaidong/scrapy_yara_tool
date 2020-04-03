rule XMRIG_Monero_Miner_Config {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-04"
    description = "Auto-generated rule - from files config.json, config.json"
    family = "None"
    hacker = "None"
    hash1 = "031333d44a3a917f9654d7e7257e00c9d961ada3bee707de94b7c7d06234909a"
    hash2 = "409b6ec82c3bdac724dae702e20cb7f80ca1e79efa4ff91212960525af016c41"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/xmrig/xmrig/releases"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "\"cpu-affinity\": null,   // set process affinity to CPU core(s), mask \"0x3\" for cores 0 and 1" fullword ascii
    $s5 = "\"nicehash\": false                  // enable nicehash/xmrig-proxy support" fullword ascii
    $s8 = "\"algo\": \"cryptonight\",  // cryptonight (default) or cryptonight-lite" fullword ascii
  condition:
    ( uint16(0) == 0x0a7b or uint16(0) == 0x0d7b ) and filesize < 5KB and 1 of them
}