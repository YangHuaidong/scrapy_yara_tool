rule Suspicious_Size_java_exe {
    meta:
        description = "Detects uncommon file size of java.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "java.exe"
        and ( filesize < 42KB or filesize > 900KB )
}