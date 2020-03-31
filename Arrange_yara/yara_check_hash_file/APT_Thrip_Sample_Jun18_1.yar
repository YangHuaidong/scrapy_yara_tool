rule APT_Thrip_Sample_Jun18_1 {
  meta:
    author = Spider
    comment = None
    date = 2018-06-21
    description = Detects sample found in Thrip report by Symantec 
    family = Jun18
    hacker = None
    hash1 = 59509a17d516813350fe1683ca6b9727bd96dd81ce3435484a5a53b472ff4ae9
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets 
    threatname = APT[Thrip]/Sample.Jun18.1
    threattype = Thrip
  strings:
    $s1 = "idocback.dll" fullword ascii
    $s2 = "constructor or from DllMain." fullword ascii
    $s3 = "appmgmt" fullword ascii
    $s4 = "chksrv" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}