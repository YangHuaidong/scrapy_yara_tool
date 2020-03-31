rule Suspicious_Size_wininit_exe {
    meta:
        description = "Detects uncommon file size of wininit.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "wininit.exe"
        and ( filesize < 90KB or filesize > 400KB )
}