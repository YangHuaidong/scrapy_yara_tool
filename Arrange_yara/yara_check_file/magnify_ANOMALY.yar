rule magnify_ANOMALY {
  meta:
    author = Spider
    comment = None
    date = 01/06/2014
    description = Abnormal magnify.exe (Magnifier) - typical strings not found in file
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 55
    threatname = magnify[ANOMALY
    threattype = ANOMALY.yar
  strings:
    $win7 = "Microsoft Screen Magnifier" wide fullword
    $win2000 = "Microsoft Magnifier" wide fullword
    $winxp = "Software\\Microsoft\\Magnify" wide
  condition:
    filename =="magnify.exe"
    and uint16(0) == 0x5a4d
    and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}