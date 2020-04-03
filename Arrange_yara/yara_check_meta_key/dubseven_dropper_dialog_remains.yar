rule dubseven_dropper_dialog_remains {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/04/18"
    description = "Searches for related dialog remnants. How rude."
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $dia1 = "fuckMessageBox 1.0" wide
    $dia2 = "Rundll 1.0" wide
  condition:
    uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550 and
    any of them
}