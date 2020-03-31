rule iexplore_ANOMALY {
  meta:
    author = Spider
    comment = None
    date = 23/04/2014
    description = Abnormal iexplore.exe - typical strings not found in file
    family = None
    hacker = None
    judge = unknown
    nodeepdive = 1
    reference = None
    score = 55
    threatname = iexplore[ANOMALY
    threattype = ANOMALY.yar
  strings:
    $win2003_win7_u1 = "IEXPLORE.EXE" wide nocase
    $win2003_win7_u2 = "Internet Explorer" wide fullword
    $win2003_win7_u3 = "translation" wide fullword nocase
    $win2003_win7_u4 = "varfileinfo" wide fullword nocase
  condition:
    filename == "iexplore.exe"
    and uint16(0) == 0x5a4d
    and not filepath contains "teamviewer"
    and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
    and filepath contains "C:\\"
    and not filepath contains "Package_for_RollupFix"
}