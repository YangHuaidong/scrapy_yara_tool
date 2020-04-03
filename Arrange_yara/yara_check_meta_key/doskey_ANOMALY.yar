rule doskey_ANOMALY {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/16"
    description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file doskey.exe"
    family = "None"
    hacker = "None"
    hash = "f2d1995325df0f3ca6e7b11648aa368b7e8f1c7f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "not set"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "Keyboard History Utility" fullword wide
  condition:
    filename == "doskey.exe"
    and uint16(0) == 0x5a4d
    and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}