rule dubseven_dropper_registry_checks {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/04/18"
    description = "Searches for registry keys checked for by the dropper"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $reg1 = "SOFTWARE\\360Safe\\Liveup"
    $reg2 = "Software\\360safe"
    $reg3 = "SOFTWARE\\kingsoft\\Antivirus"
    $reg4 = "SOFTWARE\\Avira\\Avira Destop"
    $reg5 = "SOFTWARE\\rising\\RAV"
    $reg6 = "SOFTWARE\\JiangMin"
    $reg7 = "SOFTWARE\\Micropoint\\Anti-Attack"
  condition:
    uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550 and
    all of ($reg*)
}