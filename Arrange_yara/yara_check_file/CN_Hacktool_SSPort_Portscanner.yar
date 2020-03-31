rule CN_Hacktool_SSPort_Portscanner {
  meta:
    author = Spider
    comment = None
    date = 12.10.2014
    description = Detects a chinese Portscanner named SSPort
    family = Portscanner
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = CN[Hacktool]/SSPort.Portscanner
    threattype = Hacktool
  strings:
    $s0 = "Golden Fox" fullword wide
    $s1 = "Syn Scan Port" fullword wide
    $s2 = "CZ88.NET" fullword wide
  condition:
    all of them
}