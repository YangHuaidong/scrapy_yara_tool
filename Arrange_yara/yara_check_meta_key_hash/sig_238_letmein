rule sig_238_letmein {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file letmein.exe"
    family = "None"
    hacker = "None"
    hash = "74d223a56f97b223a640e4139bb9b94d8faa895d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Error get globalgroup memebers: NERR_InvalidComputer" fullword ascii
    $s6 = "Error get users from server!" fullword ascii
    $s7 = "get in nt by name and null" fullword ascii
    $s16 = "get something from nt, hold by killusa." fullword ascii
  condition:
    all of them
}