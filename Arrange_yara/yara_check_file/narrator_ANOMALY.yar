rule narrator_ANOMALY {
  meta:
    author = Spider
    comment = None
    date = 01/06/2014
    description = Abnormal narrator.exe - typical strings not found in file
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 55
    threatname = narrator[ANOMALY
    threattype = ANOMALY.yar
  strings:
    $win7 = "Microsoft-Windows-Narrator" wide fullword
    $win2000 = "&About Narrator..." wide fullword
    $win2012 = "Screen Reader" wide fullword
    $winxp = "Software\\Microsoft\\Narrator"
    $winxp_en = "SOFTWARE\\Microsoft\\Speech\\Voices" wide
  condition:
    filename == "narrator.exe"
    and uint16(0) == 0x5a4d
    and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}