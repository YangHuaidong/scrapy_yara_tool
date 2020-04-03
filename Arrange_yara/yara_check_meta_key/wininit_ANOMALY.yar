rule wininit_ANOMALY {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/16"
    description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file wininit.exe"
    family = "None"
    hacker = "None"
    hash = "2de5c051c0d7d8bcc14b1ca46be8ab9756f29320"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "not set"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Windows Start-Up Application" fullword wide
  condition:
    filename == "wininit.exe"
    and uint16(0) == 0x5a4d
    and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}