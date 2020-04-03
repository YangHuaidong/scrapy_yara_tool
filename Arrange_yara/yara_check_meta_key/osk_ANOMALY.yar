rule osk_ANOMALY {
  meta:
    author = "Spider"
    comment = "None"
    date = "01/06/2014"
    description = "Abnormal osk.exe (On Screen Keyboard) - typical strings not found in file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 55
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Accessibility On-Screen Keyboard" wide fullword
    $s2 = "\\oskmenu" wide fullword
    $s3 = "&About On-Screen Keyboard..." wide fullword
    $s4 = "Software\\Microsoft\\Osk" wide
  condition:
    filename == "osk.exe"
    and uint16(0) == 0x5a4d
    and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}