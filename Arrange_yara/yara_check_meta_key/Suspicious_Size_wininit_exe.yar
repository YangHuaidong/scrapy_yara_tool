rule Suspicious_Size_wininit_exe {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-12-23"
    description = "Detects uncommon file size of wininit.exe"
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
    and filename == "wininit.exe"
    and ( filesize < 90KB or filesize > 400KB )
}