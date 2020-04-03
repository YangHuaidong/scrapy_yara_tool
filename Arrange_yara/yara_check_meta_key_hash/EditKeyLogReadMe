rule EditKeyLogReadMe {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file EditKeyLogReadMe.txt"
    family = "None"
    hacker = "None"
    hash = "dfa90540b0e58346f4b6ea12e30c1404e15fbe5a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "editKeyLog.exe KeyLog.exe," fullword ascii
    $s1 = "WinEggDrop.DLL" fullword ascii
    $s2 = "nc.exe" fullword ascii
    $s3 = "KeyLog.exe" fullword ascii
    $s4 = "EditKeyLog.exe" fullword ascii
    $s5 = "wineggdrop" fullword ascii
  condition:
    3 of them
}