rule Suspicious_Size_spoolsv_exe {
  meta:
    author = Spider
    comment = None
    date = 2015-12-23
    description = Detects uncommon file size of spoolsv.exe
    family = exe
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    noarchivescan = 1
    reference = None
    score = 60
    threatname = Suspicious[Size]/spoolsv.exe
    threattype = Size
  condition:
    uint16(0) == 0x5a4d
    and filename == "spoolsv.exe"
    and ( filesize < 50KB or filesize > 930KB )
}