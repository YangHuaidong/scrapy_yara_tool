rule conhost_ANOMALY {
  meta:
    author = Spider
    comment = None
    date = 2015/03/16
    description = Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file conhost.exe
    family = None
    hacker = None
    hash = 1bd846aa22b1d63a1f900f6d08d8bfa8082ae4db
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = not set
    threatname = conhost[ANOMALY
    threattype = ANOMALY.yar
  strings:
    $s2 = "Console Window Host" fullword wide
  condition:
    filename == "conhost.exe"
    and uint16(0) == 0x5a4d
    and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}