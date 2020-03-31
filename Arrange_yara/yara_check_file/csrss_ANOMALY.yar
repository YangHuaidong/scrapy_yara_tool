rule csrss_ANOMALY {
  meta:
    author = Spider
    comment = None
    date = 2015/03/16
    description = Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file csrss.exe
    family = None
    hacker = None
    hash = 17542707a3d9fa13c569450fd978272ef7070a77
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = not set
    threatname = csrss[ANOMALY
    threattype = ANOMALY.yar
  strings:
    $s1 = "Client Server Runtime Process" fullword wide
    $s4 = "name=\"Microsoft.Windows.CSRSS\"" fullword ascii
    $s5 = "CSRSRV.dll" fullword ascii
    $s6 = "CsrServerInitialization" fullword ascii
  condition:
    filename == "csrss.exe"
    and uint16(0) == 0x5a4d
    and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}