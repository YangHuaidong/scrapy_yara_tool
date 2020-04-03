rule APT17_Sample_FXSST_DLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-05-14"
    description = "Detects Samples related to APT17 activity - file FXSST.DLL"
    family = "None"
    hacker = "None"
    hash = "52f1add5ad28dc30f68afda5d41b354533d8bce3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/ZiJyQv"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Microsoft? Windows? Operating System" fullword wide
    $x2 = "fxsst.dll" fullword ascii
    $y1 = "DllRegisterServer" fullword ascii
    $y2 = ".cSV" fullword ascii
    $s1 = "GetLastActivePopup"
    $s2 = "Sleep"
    $s3 = "GetModuleFileName"
    $s4 = "VirtualProtect"
    $s5 = "HeapAlloc"
    $s6 = "GetProcessHeap"
    $s7 = "GetCommandLine"
  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and
    ( all of ($x*) or all of ($y*) ) and all of ($s*)
}