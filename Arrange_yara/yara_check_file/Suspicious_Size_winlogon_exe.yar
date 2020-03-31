rule Suspicious_Size_winlogon_exe {
  meta:
    author = Spider
    comment = None
    date = 2015-12-21
    description = Detects uncommon file size of winlogon.exe
    family = exe
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    noarchivescan = 1
    reference = None
    score = 60
    threatname = Suspicious[Size]/winlogon.exe
    threattype = Size
  condition:
    uint16(0) == 0x5a4d
    and filename == "winlogon.exe"
    and ( filesize < 279KB or filesize > 970KB )
}