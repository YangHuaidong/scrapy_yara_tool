rule notepad_ANOMALY {
  meta:
    author = "Spider"
    comment = "None"
    date = "01/06/2014"
    description = "Abnormal notepad.exe - typical strings not found in file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 55
    threatname = "None"
    threattype = "None"
  strings:
    $win7 = "HELP_ENTRY_ID_NOTEPAD_HELP" wide fullword
    $win2000 = "Do you want to create a new file?" wide fullword
    $win2003 = "Do you want to save the changes?" wide
    $winxp = "Software\\Microsoft\\Notepad" wide
    $winxp_de = "Software\\Microsoft\\Notepad" wide
  condition:
    filename == "notepad.exe"
    and uint16(0) == 0x5a4d
    and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}