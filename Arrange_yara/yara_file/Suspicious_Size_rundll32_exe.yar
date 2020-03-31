rule Suspicious_Size_rundll32_exe {
    meta:
        description = "Detects uncommon file size of rundll32.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "rundll32.exe"
        and ( filesize < 30KB or filesize > 80KB )
}