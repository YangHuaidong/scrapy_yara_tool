rule Suspicious_Size_iexplore_exe {
  meta:
    author = Spider
    comment = None
    date = 2015-12-21
    description = Detects uncommon file size of iexplore.exe
    family = exe
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    noarchivescan = 1
    reference = None
    score = 60
    threatname = Suspicious[Size]/iexplore.exe
    threattype = Size
  condition:
    uint16(0) == 0x5a4d
    and filename == "iexplore.exe"
    and not filepath contains "teamviewer"
    and ( filesize < 75KB or filesize > 910KB )
}