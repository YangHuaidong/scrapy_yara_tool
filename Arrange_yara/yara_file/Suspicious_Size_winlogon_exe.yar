rule Suspicious_Size_winlogon_exe {
    meta:
        description = "Detects uncommon file size of winlogon.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "winlogon.exe"
        and ( filesize < 279KB or filesize > 970KB )
}