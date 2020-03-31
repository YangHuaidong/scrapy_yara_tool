rule Suspicious_Size_csrss_exe {
  meta:
    author = Spider
    comment = None
    date = 2015-12-21
    description = Detects uncommon file size of csrss.exe
    family = exe
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    noarchivescan = 1
    reference = None
    score = 60
    threatname = Suspicious[Size]/csrss.exe
    threattype = Size
  condition:
    uint16(0) == 0x5a4d
    and filename == "csrss.exe"
    and ( filesize > 18KB )
}