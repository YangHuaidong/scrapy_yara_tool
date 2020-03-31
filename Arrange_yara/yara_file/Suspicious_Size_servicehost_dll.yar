rule Suspicious_Size_servicehost_dll {
    meta:
        description = "Detects uncommon file size of servicehost.dll"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "servicehost.dll"
        and filesize > 150KB
}