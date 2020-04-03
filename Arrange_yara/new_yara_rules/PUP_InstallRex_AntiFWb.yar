rule PUP_InstallRex_AntiFWb {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-05-13"
    description = "Malware InstallRex / AntiFW"
    family = "None"
    hacker = "None"
    hash = "bb5607cd2ee51f039f60e32cf7edc4e21a2d95cd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 55
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "Error %u while loading TSU.DLL %ls" fullword ascii
    $s7 = "GetModuleFileName() failed => %u" fullword ascii
    $s8 = "TSULoader.exe" fullword wide
    $s15 = "\\StringFileInfo\\%04x%04x\\Arguments" fullword wide
    $s17 = "Tsu%08lX.dll" fullword wide
  condition:
    uint16(0) == 0x5a4d and all of them
}