rule PlugX_J16_Gen2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-08"
    description = "Detects PlugX Malware Samples from June 2016"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "VT Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "XPlugKeyLogger.cpp" fullword ascii
    $s2 = "XPlugProcess.cpp" fullword ascii
    $s4 = "XPlgLoader.cpp" fullword ascii
    $s5 = "XPlugPortMap.cpp" fullword ascii
    $s8 = "XPlugShell.cpp" fullword ascii
    $s11 = "file: %s, line: %d, error: [%d]%s" fullword ascii
    $s12 = "XInstall.cpp" fullword ascii
    $s13 = "XPlugTelnet.cpp" fullword ascii
    $s14 = "XInstallUAC.cpp" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 600KB and ( 2 of ($s*) ) ) or ( 5 of them )
}