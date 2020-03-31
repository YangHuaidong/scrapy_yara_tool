rule CN_Honker_CnCerT_CCdoor_CMD {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file CnCerT.CCdoor.CMD.dll
    family = CCdoor
    hacker = None
    hash = 1c6ed7d817fa8e6534a5fd36a94f4fc2f066c9cd
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/CnCerT.CCdoor.CMD
    threattype = Honker
  strings:
    $s2 = "CnCerT.CCdoor.CMD.dll" fullword wide
    $s3 = "cmdpath" fullword ascii
    $s4 = "Get4Bytes" fullword ascii
    $s5 = "ExcuteCmd" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 22KB and all of them
}