rule sig_238_listip {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file listip.exe"
    family = "None"
    hacker = "None"
    hash = "f32a0c5bf787c10eb494eb3b83d0c7a035e7172b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "ERROR!!! Bad host lookup. Program Terminate." fullword ascii
    $s2 = "ERROR No.2!!! Program Terminate." fullword ascii
    $s4 = "Local Host Name: %s" fullword ascii
    $s5 = "Packed by exe32pack 1.38" fullword ascii
    $s7 = "Local Computer Name: %s" fullword ascii
    $s8 = "Local IP Adress: %s" fullword ascii
  condition:
    all of them
}