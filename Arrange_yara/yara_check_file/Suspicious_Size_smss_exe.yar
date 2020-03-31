rule Suspicious_Size_smss_exe {
  meta:
    author = Spider
    comment = None
    date = 2015-12-23
    description = Detects uncommon file size of smss.exe
    family = exe
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    noarchivescan = 1
    reference = None
    score = 60
    threatname = Suspicious[Size]/smss.exe
    threattype = Size
  condition:
    uint16(0) == 0x5a4d
    and filename == "smss.exe"
    and ( filesize < 40KB or filesize > 320KB )
}