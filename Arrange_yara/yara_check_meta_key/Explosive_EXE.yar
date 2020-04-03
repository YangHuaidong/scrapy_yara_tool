rule Explosive_EXE : APT {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Explosion/Explosive Malware - Volatile Cedar APT"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $DLD_S = "DLD-S:"
    $DLD_E = "DLD-E:"
  condition:
    all of them and
    uint16(0) == 0x5A4D
}