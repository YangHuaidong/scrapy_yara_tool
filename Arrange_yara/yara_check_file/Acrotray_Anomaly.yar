rule Acrotray_Anomaly {
  meta:
    author = Spider
    comment = None
    date = None
    description = Detects an acrotray.exe that does not contain the usual strings
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 75
    threatname = Acrotray[Anomaly
    threattype = Anomaly.yar
  strings:
    $s1 = "PDF/X-3:2002" fullword wide
    $s2 = "AcroTray - Adobe Acrobat Distiller helper application" fullword wide
    $s3 = "MS Sans Serif" fullword wide
    $s4 = "COOLTYPE.DLL" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB
    and ( filename == "acrotray.exe" or filename == "AcroTray.exe" )
    and not all of ($s*)
}