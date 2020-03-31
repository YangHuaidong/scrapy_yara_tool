rule Suspicious_Size_explorer_exe {
  meta:
    author = Spider
    comment = None
    date = 2015-12-21
    description = Detects uncommon file size of explorer.exe
    family = exe
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    noarchivescan = 1
    reference = None
    score = 60
    threatname = Suspicious[Size]/explorer.exe
    threattype = Size
  condition:
    uint16(0) == 0x5a4d
    and filename == "explorer.exe"
    and not filepath contains "teamviewer"
    and ( filesize < 800KB or filesize > 5000KB )
}