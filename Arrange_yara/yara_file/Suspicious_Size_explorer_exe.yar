rule Suspicious_Size_explorer_exe {
    meta:
        description = "Detects uncommon file size of explorer.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "explorer.exe"
        and not filepath contains "teamviewer"
        and ( filesize < 800KB or filesize > 5000KB )
}