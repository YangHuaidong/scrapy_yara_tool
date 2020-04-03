rule Suspicious_Size_iexplore_exe {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-12-21"
    description = "Detects uncommon file size of iexplore.exe"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    noarchivescan = 1
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x5a4d
    and filename == "iexplore.exe"
    and not filepath contains "teamviewer"
    and ( filesize < 75KB or filesize > 910KB )
}