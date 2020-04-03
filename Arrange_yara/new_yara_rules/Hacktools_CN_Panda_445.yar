rule Hacktools_CN_Panda_445 {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file 445.rar"
    family = "None"
    hacker = "None"
    hash = "a61316578bcbde66f39d88e7fc113c134b5b966b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "for /f %%i in (ips.txt) do (start cmd.bat %%i)" fullword ascii
    $s1 = "445\\nc.exe" fullword ascii
    $s2 = "445\\s.exe" fullword ascii
    $s3 = "cs.exe %1" fullword ascii
    $s4 = "445\\cs.exe" fullword ascii
    $s5 = "445\\ip.txt" fullword ascii
    $s6 = "445\\cmd.bat" fullword ascii
    $s9 = "@echo off" fullword ascii
  condition:
    all of them
}