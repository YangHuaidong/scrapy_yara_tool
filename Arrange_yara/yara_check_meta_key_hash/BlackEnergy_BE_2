rule BlackEnergy_BE_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/02/19"
    description = "Detects BlackEnergy 2 Malware"
    family = "None"
    hacker = "None"
    hash = "983cfcf3aaaeff1ad82eb70f77088ad6ccedee77"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/DThzLz"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<description> Windows system utility service  </description>" fullword ascii
    $s1 = "WindowsSysUtility - Unicode" fullword wide
    $s2 = "msiexec.exe" fullword wide
    $s3 = "WinHelpW" fullword ascii
    $s4 = "ReadProcessMemory" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 250KB and all of ($s*)
}