rule explorer_ANOMALY {
  meta:
    author = "Spider"
    comment = "None"
    date = "27/05/2014"
    description = "Abnormal explorer.exe - typical strings not found in file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 55
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "EXPLORER.EXE" wide fullword
    $s2 = "Windows Explorer" wide fullword
  condition:
    filename == "explorer.exe"
    and uint16(0) == 0x5a4d
    and not filepath contains "teamviewer"
    and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}