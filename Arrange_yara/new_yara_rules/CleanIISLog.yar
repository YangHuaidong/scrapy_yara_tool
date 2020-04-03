rule CleanIISLog {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file CleanIISLog.exe"
    family = "None"
    hacker = "None"
    hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "CleanIP - Specify IP Address Which You Want Clear." fullword ascii
    $s2 = "LogFile - Specify Log File Which You Want Process." fullword ascii
    $s8 = "CleanIISLog Ver" fullword ascii
    $s9 = "msftpsvc" fullword ascii
    $s10 = "Fatal Error: MFC initialization failed" fullword ascii
    $s11 = "Specified \"ALL\" Will Process All Log Files." fullword ascii
    $s12 = "Specified \".\" Will Clean All IP Record." fullword ascii
    $s16 = "Service %s Stopped." fullword ascii
    $s20 = "Process Log File %s..." fullword ascii
  condition:
    5 of them
}