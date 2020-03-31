rule Suspicious_Size_chrome_exe {
    meta:
        description = "Detects uncommon file size of chrome.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "chrome.exe"
        and ( filesize < 500KB or filesize > 2000KB )
}