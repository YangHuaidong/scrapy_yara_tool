rule Utilman_ANOMALY {
  meta:
    author = Spider
    comment = None
    date = 01/06/2014
    description = Abnormal utilman.exe - typical strings not found in file
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = Utilman[ANOMALY
    threattype = ANOMALY.yar
  strings:
    $win7 = "utilman.exe" wide fullword
    $win2000 = "Start with Utility Manager" fullword wide
    $win2012 = "utilman2.exe" fullword wide
  condition:
    ( filename == "utilman.exe" or filename == "Utilman.exe" )
    and uint16(0) == 0x5a4d
    and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}