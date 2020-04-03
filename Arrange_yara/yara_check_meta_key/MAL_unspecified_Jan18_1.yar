rule MAL_unspecified_Jan18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-19"
    description = "Detects unspecified malware sample"
    family = "None"
    hacker = "None"
    hash1 = "f87879b29ff83616e9c9044bd5fb847cf5d2efdd2f01fc284d1a6ce7d464a417"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
    $s2 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" fullword ascii
    $s3 = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
    $s4 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" fullword ascii
    $s5 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
    $s6 = "%s\\%s.bat" fullword ascii
    $s7 = "DEL /s \"%s\" >nul 2>&1" fullword ascii
  condition:
    filesize < 300KB and 2 of them
}