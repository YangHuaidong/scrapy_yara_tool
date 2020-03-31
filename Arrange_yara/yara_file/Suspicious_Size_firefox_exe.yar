rule Suspicious_Size_firefox_exe {
    meta:
        description = "Detects uncommon file size of firefox.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "firefox.exe"
        and ( filesize < 265KB or filesize > 910KB )
}