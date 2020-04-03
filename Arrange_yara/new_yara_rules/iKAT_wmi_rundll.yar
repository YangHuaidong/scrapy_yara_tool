rule iKAT_wmi_rundll {
  meta:
    author = "Spider"
    comment = "None"
    date = "05.11.14"
    description = "This exe will attempt to use WMI to Call the Win32_Process event to spawn rundll - file wmi_rundll.exe"
    family = "None"
    hacker = "None"
    hash = "97c4d4e6a644eed5aa12437805e39213e494d120"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "This operating system is not supported." fullword ascii
    $s1 = "Error!" fullword ascii
    $s2 = "Win32 only!" fullword ascii
    $s3 = "COMCTL32.dll" fullword ascii
    $s4 = "[LordPE]" ascii
    $s5 = "CRTDLL.dll" fullword ascii
    $s6 = "VBScript" fullword ascii
    $s7 = "CoUninitialize" fullword ascii
  condition:
    all of them and filesize < 15KB
}