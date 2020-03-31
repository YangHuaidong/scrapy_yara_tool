rule Suspicious_Size_wininit_exe {
  meta:
    author = Spider
    comment = None
    date = 2015-12-23
    description = Detects uncommon file size of wininit.exe
    family = exe
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    noarchivescan = 1
    reference = None
    score = 60
    threatname = Suspicious[Size]/wininit.exe
    threattype = Size
  condition:
    uint16(0) == 0x5a4d
    and filename == "wininit.exe"
    and ( filesize < 90KB or filesize > 400KB )
}