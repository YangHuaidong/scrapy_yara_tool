rule APT_Thrip_Sample_Jun18_16 {
  meta:
    author = Spider
    comment = None
    date = 2018-06-21
    description = Detects sample found in Thrip report by Symantec 
    family = Jun18
    hacker = None
    hash1 = 2b1c1c6d82837dbbccd171a0413c1d761b1f7c3668a21c63ca06143e731f030e
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets 
    threatname = APT[Thrip]/Sample.Jun18.16
    threattype = Thrip
  strings:
    $s1 = "[%d] Failed, %08X" fullword ascii
    $s2 = "woqunimalegebi" fullword ascii
    $s3 = "[%d] Offset can not fetched." fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB
    and ( all of them or pe.imphash() == "c6a4c95d868a3327a62c9c45f5e15bbf" )
}