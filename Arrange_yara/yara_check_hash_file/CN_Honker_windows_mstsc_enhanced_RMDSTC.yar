rule CN_Honker_windows_mstsc_enhanced_RMDSTC {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file RMDSTC.exe
    family = mstsc
    hacker = None
    hash = 3ca2b1b6f31219baf172abcc8f00f07f560e465f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/windows.mstsc.enhanced.RMDSTC
    threattype = Honker
  strings:
    $s0 = "zava zir5@163.com" fullword wide
    $s1 = "By newccc" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and all of them
}