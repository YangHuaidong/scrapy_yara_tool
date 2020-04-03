rule APT_Cloaked_ScanLine {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014-07-18"
    description = "Looks like a cloaked ScanLine Port Scanner. May be APT group activity."
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "ScanLine" wide fullword
    $s1 = "Command line port scanner" wide fullword
    $s2 = "sl.exe" wide fullword
  condition:
    uint16(0) == 0x5a4d and $s0 and $s1 and $s2 and not filename == "sl.exe"
}