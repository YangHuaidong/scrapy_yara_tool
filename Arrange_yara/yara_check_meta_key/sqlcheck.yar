rule sqlcheck {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file sqlcheck.exe"
    family = "None"
    hacker = "None"
    hash = "5a5778ac200078b627db84fdc35bf5bcee232dc7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Power by eyas<cooleyas@21cn.com>" fullword ascii
    $s3 = "\\ipc$ \"\" /user:\"\"" fullword ascii
    $s4 = "SQLCheck can only scan a class B network. Try again." fullword ascii
    $s14 = "Example: SQLCheck 192.168.0.1 192.168.0.254" fullword ascii
    $s20 = "Usage: SQLCheck <StartIP> <EndIP>" fullword ascii
  condition:
    3 of them
}