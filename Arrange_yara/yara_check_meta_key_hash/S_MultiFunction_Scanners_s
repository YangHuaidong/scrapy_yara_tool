rule S_MultiFunction_Scanners_s {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file s.exe"
    family = "None"
    hacker = "None"
    hash = "79b60ffa1c0f73b3c47e72118e0f600fcd86b355"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "C:\\WINDOWS\\temp\\pojie.exe /l=" fullword ascii
    $s1 = "C:\\WINDOWS\\temp\\s.exe" fullword ascii
    $s2 = "C:\\WINDOWS\\temp\\s.exe tcp " fullword ascii
    $s3 = "explorer.exe http://www.hackdos.com" fullword ascii
    $s4 = "C:\\WINDOWS\\temp\\pojie.exe" fullword ascii
    $s5 = "Failed to read file or invalid data in file!" fullword ascii
    $s6 = "www.hackdos.com" fullword ascii
    $s7 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
    $s11 = "The interface of kernel library is invalid!" fullword ascii
    $s12 = "eventvwr" fullword ascii
    $s13 = "Failed to decompress data!" fullword ascii
    $s14 = "NOTEPAD.EXE result.txt" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 8000KB and 4 of them
}