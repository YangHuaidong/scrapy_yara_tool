rule aolipsniffer {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file aolipsniffer.exe"
    family = "None"
    hacker = "None"
    hash = "51565754ea43d2d57b712d9f0a3e62b8"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
    $s1 = "dwGetAddressForObject"
    $s2 = "Color Transfer Settings"
    $s3 = "FX Global Lighting Angle"
    $s4 = "Version compatibility info"
    $s5 = "New Windows Thumbnail"
    $s6 = "Layer ID Generator Base"
    $s7 = "Color Halftone Settings"
    $s8 = "C:\\WINDOWS\\SYSTEM\\MSWINSCK.oca"
  condition:
    all of them
}