rule SUSP_XMRIG_String {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-12-28"
    description = "Detects a suspicious XMRIG crypto miner executable string in filr"
    family = "None"
    hacker = "None"
    hash1 = "eb18ae69f1511eeb4ed9d4d7bcdf3391a06768f384e94427f4fc3bd21b383127"
    judge = "unknown"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "xmrig.exe" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}