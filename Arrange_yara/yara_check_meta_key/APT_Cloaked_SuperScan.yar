rule APT_Cloaked_SuperScan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014-07-18"
    description = "Looks like a cloaked SuperScan Port Scanner. May be APT group activity."
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "SuperScan4.exe" wide fullword
    $s1 = "Foundstone Inc." wide fullword
  condition:
    uint16(0) == 0x5a4d and $s0 and $s1 and not filename contains "superscan"
}