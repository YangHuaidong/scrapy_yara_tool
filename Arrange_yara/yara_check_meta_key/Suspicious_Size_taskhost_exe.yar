rule Suspicious_Size_taskhost_exe {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-12-23"
    description = "Detects uncommon file size of taskhost.exe"
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
    and filename == "taskhost.exe"
    and ( filesize < 45KB or filesize > 120KB )
}