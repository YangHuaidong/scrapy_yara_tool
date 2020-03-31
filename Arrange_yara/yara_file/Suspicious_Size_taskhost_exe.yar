rule Suspicious_Size_taskhost_exe {
    meta:
        description = "Detects uncommon file size of taskhost.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "taskhost.exe"
        and ( filesize < 45KB or filesize > 120KB )
}