rule CN_Honker_CoolScan_scan {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file scan.exe
    family = scan
    hacker = None
    hash = e1c5fb6b9f4e92c4264c7bea7f5fba9a5335c328
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/CoolScan.scan
    threattype = Honker
  strings:
    $s0 = "User-agent:\\s{0,32}(huasai|huasai/1.0|\\*)" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "scan web.exe" fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 3680KB and all of them
}